// Command pulse-agent runs availability checks assigned by the Pulse control
// plane and reports back status codes and timings.
//
// What it does, in full:
//   - polls one server (the --server flag) for check tasks;
//   - makes read-only GET/HEAD requests to public web servers named in those
//     tasks, over ports 80/443 only;
//   - reports which stage succeeded (DNS/TCP/TLS/HTTP), how long each took,
//     and the HTTP status code.
//
// What it will not do, enforced in internal/guardrails regardless of what the
// server sends: exceed 30 checks/minute, hit the same host more often than
// once per 20s, connect to a private or reserved address, use any method other
// than GET/HEAD, read or transmit a response body, execute anything, or relay
// third-party traffic. It needs no root or Administrator rights.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ru-pulse/pulse-agent/internal/applog"
	"github.com/ru-pulse/pulse-agent/internal/client"
	"github.com/ru-pulse/pulse-agent/internal/guardrails"
	"github.com/ru-pulse/pulse-agent/internal/identity"
	"github.com/ru-pulse/pulse-agent/internal/localui"
	"github.com/ru-pulse/pulse-agent/internal/settings"
	"github.com/ru-pulse/pulse-agent/internal/supervisor"
	"github.com/ru-pulse/pulse-agent/internal/tray"
)

// Stamped at build time:
//
//	-ldflags "-X main.Version=0.1.0 -X main.DefaultServer=https://ru-pulse.ru"
//
// DefaultServer matters for distribution: a partner who double-clicks the
// binary must land on the real control plane without typing flags. It stays a
// default, not a constant — --server and PULSE_SERVER still win, so anyone
// auditing or self-hosting can point it wherever they like.
var (
	Version       = "0.1.0-dev"
	DefaultServer = "http://localhost:8787"
)

var log *applog.Logger

func main() {
	serverURL := flag.String("server", envOr("PULSE_SERVER", DefaultServer), "control plane base URL")
	city := flag.String("city", os.Getenv("PULSE_CITY"), "optional city label shown to the operator")
	partnerCode := flag.String("partner-code", os.Getenv("PULSE_PARTNER_CODE"), "partner referral code")
	identityPath := flag.String("identity", os.Getenv("PULSE_IDENTITY"), "path to identity.json")
	showLimits := flag.Bool("limits", false, "print the hard-coded safety limits and exit")
	showStatus := flag.Bool("status", false, "show binding and reputation, then exit")
	headless := flag.Bool("headless", false, "run without the tray icon and settings window")
	flag.Parse()

	// Под Windows приложение собрано без консоли; если его запустили из cmd,
	// вывод надо вернуть туда, иначе диагностические флаги печатают в никуда.
	attachParentConsole()

	if *showLimits {
		printLimits()
		return
	}

	if *identityPath == "" {
		path, err := identity.DefaultPath()
		if err != nil {
			fatal("cannot determine home directory: %v", err)
		}
		*identityPath = path
	}

	logger, err := applog.New(filepath.Join(filepath.Dir(*identityPath), "agent.log"), os.Stdout)
	if err != nil {
		fatal("cannot open log file: %v", err)
	}
	log = logger
	defer log.Close()

	printBanner(*serverURL, *identityPath)

	id, err := identity.LoadOrCreate(*identityPath)
	if err != nil {
		fatal("identity: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := client.New(*serverURL, id, Version)

	if !id.IsRegistered() {
		if err := registerWithRetry(ctx, api, *city, *partnerCode); err != nil {
			if client.IsUnknownPartnerCode(err) {
				fatal("partner code %q is not recognised by the server.\n"+
					"Check it against the code shown in your partner account and run again.", *partnerCode)
			}
			fatal("registration failed: %v", err)
		}
		log.Printf("registered as %s; server key pinned", id.File.AgentID)
	} else if err := api.VerifyPinnedServerKey(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "\nSECURITY: %v\n", err)
		fmt.Fprintf(os.Stderr, "The control plane is presenting a different signing key than the one this\n")
		fmt.Fprintf(os.Stderr, "agent pinned on first run. Refusing to run. If this change is expected,\n")
		fmt.Fprintf(os.Stderr, "delete %s and re-register.\n", id.Path)
		os.Exit(2)
	}

	// Код, переданный уже зарегистрированному агенту, означает «привяжи меня к
	// этому партнёру»: забывший флаг при установке чинит это одной командой, не
	// теряя накопленную репутацию.
	if *partnerCode != "" && id.IsRegistered() {
		if err := api.Bind(ctx, *partnerCode); err != nil {
			if client.IsUnknownPartnerCode(err) {
				fatal("partner code %q is not recognised by the server.", *partnerCode)
			}
			log.Printf("could not bind to partner: %v", err)
		} else {
			log.Printf("bound to partner code %s", *partnerCode)
		}
	}

	if *showStatus {
		printStatus(ctx, api)
		return
	}

	settingsPath := filepath.Join(filepath.Dir(*identityPath), "settings.json")
	store, err := settings.Load(settingsPath)
	if err != nil {
		fatal("settings: %v", err)
	}
	if *city != "" {
		_, _ = store.Update(func(s *settings.Settings) { s.City = *city })
	}

	sup := supervisor.New(api, id, store, log.Printf)
	go sup.Run(ctx)

	if *headless {
		log.Printf("running headless; settings window disabled")
		<-ctx.Done()
		return
	}

	ui, err := localui.New(store, sup, api, id.File.AgentID, log.Printf)
	if err != nil {
		fatal("settings window: %v", err)
	}
	uiURL, err := ui.Start()
	if err != nil {
		fatal("settings window: %v", err)
	}
	defer ui.Close()
	log.Printf("settings window: %s", uiURL)

	runTray(ctx, stop, sup, store, uiURL)
}

// runTray держит иконку в трее; на платформах без трея просто ждёт завершения.
func runTray(
	ctx context.Context, stop context.CancelFunc,
	sup *supervisor.Supervisor, store *settings.Store, uiURL string,
) {
	controller, err := tray.Run(tray.Options{
		Tooltip:        "Пульс Рунета",
		OnOpenSettings: func() { openBrowser(uiURL) },
		OnOpenLog:      func() { openBrowser("file://" + log.Path()) },
		OnToggle: func() {
			next, err := store.Update(func(s *settings.Settings) {
				s.Active = !s.Active
				s.PausedUntil = time.Time{}
			})
			if err != nil {
				log.Printf("could not save settings: %v", err)
				return
			}
			sup.ApplySettings(next)
		},
		OnQuit: stop,
	})
	if err != nil {
		if err != tray.ErrUnsupported {
			log.Printf("tray unavailable: %v", err)
		}
		fmt.Printf("\nОкно настроек: %s\n\n", uiURL)
		<-ctx.Done()
		return
	}
	defer controller.Stop()

	sup.OnChange(func(state supervisor.State) {
		controller.SetStatus(trayStatus(state), trayTooltip(state))
	})
	controller.SetStatus(trayStatus(sup.State()), trayTooltip(sup.State()))

	<-ctx.Done()
}

func trayStatus(state supervisor.State) tray.Status {
	switch {
	case !state.Working:
		return tray.StatusStopped
	case !state.Connected:
		return tray.StatusAttention
	default:
		return tray.StatusWorking
	}
}

func trayTooltip(state supervisor.State) string {
	if !state.Working {
		return "Пульс Рунета — остановлен"
	}
	if !state.Connected {
		return "Пульс Рунета — нет связи с сервером"
	}
	return fmt.Sprintf("Пульс Рунета — работает, проверок сегодня: %d", state.ChecksToday)
}

func registerWithRetry(ctx context.Context, api *client.Client, city, partnerCode string) error {
	var lastErr error
	for attempt := 1; attempt <= 10 && ctx.Err() == nil; attempt++ {
		err := api.Register(ctx, city, partnerCode)
		if err == nil {
			return nil
		}
		// Неверный код не станет верным от повторов — выходим сразу.
		if client.IsUnknownPartnerCode(err) {
			return err
		}
		lastErr = err
		wait := time.Duration(attempt*2) * time.Second
		log.Printf("registration attempt %d failed (%v) — retrying in %s", attempt, err, wait)
		sleepCtx(ctx, wait)
	}
	return lastErr
}

func printStatus(ctx context.Context, api *client.Client) {
	status, err := api.Status(ctx)
	if err != nil {
		fatal("could not fetch status: %v", err)
	}
	fmt.Printf("\nПривязка   : ")
	if status.BoundToPartner {
		fmt.Printf("партнёр %s\n", status.PartnerEmail)
	} else {
		fmt.Printf("НЕТ — проверки выполняются, но ни за кем не числятся\n")
	}
	fmt.Printf("Репутация  : %d\n", status.Reputation)
	fmt.Printf("Проверок   : %d\n", status.ChecksServed)
	fmt.Printf("Сеть       : %s", status.Network.Group)
	if status.Network.City != "" {
		fmt.Printf(" (%s, %s)", status.Network.City, status.Network.Country)
	}
	fmt.Println()
	if !status.Counted {
		fmt.Printf("\nРезультаты НЕ засчитываются сетью, причина: %s\n", explainNotCounted(status.NotCountedReason))
		if status.VPNReason != "" {
			fmt.Printf("Признак определён сервером по адресу подключения: %s\n", status.VPNReason)
		}
	}
}

// Причина всегда объясняется словами: молчаливый ноль в интерфейсе — худший
// способ сообщить человеку, что он работает впустую.
func explainNotCounted(reason string) string {
	switch reason {
	case "no_partner":
		return "агент не привязан к партнёру (запустите с --partner-code ВАШ_КОД)"
	case "vpn_or_datacenter":
		return "подключение выглядит как VPN или дата-центр — нужен обычный домашний или мобильный интернет"
	case "low_reputation":
		return "низкая репутация: агент расходится с остальными или не проходит контрольные проверки"
	case "agent_blocked":
		return "агент заблокирован оператором"
	default:
		return reason
	}
}

func printBanner(serverURL, identityPath string) {
	fmt.Printf("pulse-agent %s\n", Version)
	fmt.Printf("  control plane : %s\n", serverURL)
	fmt.Printf("  identity file : %s\n", identityPath)
	fmt.Printf("  what it sends : check stage, timings, HTTP status — never response bodies\n")
	fmt.Printf("  hard limits   : %d checks/min, %s per-target cooldown, GET/HEAD on ports 80/443 only\n",
		guardrails.MaxChecksPerMinute, guardrails.PerTargetCooldown)
	fmt.Printf("  run `pulse-agent -limits` for the full list. Source is open — read it.\n\n")
}

func printLimits() {
	fmt.Printf("pulse-agent %s — limits enforced locally, not configurable by the server:\n\n", Version)
	fmt.Printf("  max checks per minute     : %d (a user setting may only lower it)\n", guardrails.MaxChecksPerMinute)
	fmt.Printf("  per-target cooldown       : %s\n", guardrails.PerTargetCooldown)
	fmt.Printf("  max accepted task age     : %s\n", guardrails.MaxTaskAge)
	fmt.Printf("  allowed methods           : GET, HEAD\n")
	fmt.Printf("  allowed ports             : 80, 443\n")
	fmt.Printf("  private/reserved targets  : refused (checked against every resolved address)\n")
	fmt.Printf("  response body             : never read past the status line, never transmitted\n")
	fmt.Printf("  task authentication       : Ed25519, verified against the key pinned on first run\n")
	fmt.Printf("  privileges required       : none (no root, no raw sockets, no system service)\n")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func fatal(format string, args ...any) {
	if log != nil {
		log.Printf("fatal: "+format, args...)
	}
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
