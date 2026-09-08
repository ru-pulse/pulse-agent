// Package localui — окно настроек агента, реализованное как страница на
// локальном порту.
//
// Так интерфейс обходится без GUI-тулкита: агент остаётся на одной стандартной
// библиотеке, а его код по-прежнему можно прочитать за вечер. Цена решения —
// открытый TCP-порт на машине партнёра, поэтому:
//
//   - слушаем ТОЛЬКО 127.0.0.1, никогда 0.0.0.0. Иначе панель управления
//     агентом станет доступна всей локальной сети;
//   - порт выбирает ядро (:0), он не предсказуем;
//   - каждый запрос требует токен, сгенерированный при запуске. На машине с
//     несколькими пользователями loopback не является границей доверия.
package localui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ru-pulse/pulse-agent/internal/client"
	"github.com/ru-pulse/pulse-agent/internal/guardrails"
	"github.com/ru-pulse/pulse-agent/internal/settings"
	"github.com/ru-pulse/pulse-agent/internal/supervisor"
)

//go:embed page.html
var pageFS embed.FS

const cookieName = "pulse_local"

type Server struct {
	store   *settings.Store
	sup     *supervisor.Supervisor
	api     *client.Client
	agentID string
	token   string
	url     string
	http    *http.Server
	logf    func(string, ...any)
}

func New(store *settings.Store, sup *supervisor.Supervisor, api *client.Client, agentID string, logf func(string, ...any)) (*Server, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return &Server{
		store: store, sup: sup, api: api, agentID: agentID,
		token: hex.EncodeToString(raw), logf: logf,
	}, nil
}

// Start поднимает сервер на случайном порту loopback и возвращает адрес с токеном.
func (s *Server) Start() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	s.url = fmt.Sprintf("http://127.0.0.1:%d/?token=%s", port, s.token)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePage)
	mux.HandleFunc("/api/state", s.guard(s.handleState))
	mux.HandleFunc("/api/settings", s.guard(s.handleSettings))
	mux.HandleFunc("/api/bind", s.guard(s.handleBind))
	mux.HandleFunc("/api/log", s.guard(s.handleLog))

	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.http.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logf("local ui stopped: %v", err)
		}
	}()
	return s.url, nil
}

func (s *Server) URL() string { return s.url }

func (s *Server) Close() error {
	if s.http == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.http.Shutdown(ctx)
}

// guard проверяет токен постоянным по времени сравнением: интерфейс локальный,
// но подбирать его секрет соседнему процессу всё равно быть не должно.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorised(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) authorised(r *http.Request) bool {
	if cookie, err := r.Cookie(cookieName); err == nil {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.token)) == 1 {
			return true
		}
	}
	token := r.URL.Query().Get("token")
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	if !s.authorised(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Токен переезжает в cookie, чтобы не болтаться в адресной строке.
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	page, err := pageFS.ReadFile("page.html")
	if err != nil {
		http.Error(w, "page missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

type stateResponse struct {
	State     supervisor.State  `json:"state"`
	Settings  settings.Settings `json:"settings"`
	HardLimit int               `json:"hardLimit"`
	AgentID   string            `json:"agentId"`
	Server    *client.Status    `json:"server,omitempty"`
	ServerErr string            `json:"serverError,omitempty"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	resp := stateResponse{
		State:     s.sup.State(),
		Settings:  s.store.Get(),
		HardLimit: guardrails.MaxChecksPerMinute,
		AgentID:   s.agentID,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	// Данные с сервера необязательны: без связи окно обязано открываться и
	// показывать локальное состояние, а не пустой экран с ошибкой.
	if status, err := s.api.Status(ctx); err != nil {
		resp.ServerErr = err.Error()
	} else {
		resp.Server = status
	}
	writeJSON(w, resp)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Active             *bool   `json:"active"`
		MaxChecksPerMinute *int    `json:"maxChecksPerMinute"`
		City               *string `json:"city"`
		Autostart          *bool   `json:"autostart"`
		PauseMinutes       *int    `json:"pauseMinutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	next, err := s.store.Update(func(cur *settings.Settings) {
		if body.Active != nil {
			cur.Active = *body.Active
			if *body.Active {
				cur.PausedUntil = time.Time{}
			}
		}
		if body.MaxChecksPerMinute != nil {
			// Заведомо выше потолка — не ошибка: Clamp опустит до потолка.
			cur.MaxChecksPerMinute = *body.MaxChecksPerMinute
		}
		if body.City != nil {
			cur.City = *body.City
		}
		if body.Autostart != nil {
			cur.Autostart = *body.Autostart
		}
		if body.PauseMinutes != nil {
			if *body.PauseMinutes > 0 {
				cur.PausedUntil = time.Now().Add(time.Duration(*body.PauseMinutes) * time.Minute)
			} else {
				cur.PausedUntil = time.Time{}
			}
		}
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.sup.ApplySettings(next)
	writeJSON(w, map[string]any{"ok": true, "settings": next})
}

func (s *Server) handleBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PartnerCode string `json:"partnerCode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if err := s.api.Bind(ctx, body.PartnerCode); err != nil {
		message := "Не удалось привязать код."
		if client.IsUnknownPartnerCode(err) {
			message = "Сервер не знает такого кода. Проверьте его в личном кабинете."
		}
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"ok": false, "message": message, "detail": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"entries": s.sup.Recent()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
