// Package supervisor владеет рабочим циклом агента и делает его управляемым:
// пауза, возобновление, живые счётчики для интерфейса и трея.
//
// Пауза означает «не опрашивать сервер вообще», а не «опрашивать и не
// выполнять». Так сервер через минуту перестаёт считать агента онлайн и
// перестаёт раздавать ему задания — вместо того чтобы держать очередь для
// того, кто заведомо ничего не сделает.
package supervisor

import (
	"context"
	"sync"
	"time"

	"github.com/ru-pulse/pulse-agent/internal/checker"
	"github.com/ru-pulse/pulse-agent/internal/client"
	"github.com/ru-pulse/pulse-agent/internal/guardrails"
	"github.com/ru-pulse/pulse-agent/internal/identity"
	"github.com/ru-pulse/pulse-agent/internal/protocol"
	"github.com/ru-pulse/pulse-agent/internal/settings"
	"github.com/ru-pulse/pulse-agent/internal/vpnhint"
)

type CheckLogEntry struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Domain string    `json:"domain"`
	Stage  string    `json:"stage"`
	Status int       `json:"status"`
	Error  string    `json:"error,omitempty"`
	Ms     int64     `json:"ms"`
}

// State — то, что показывают трей и локальная страница.
type State struct {
	Working       bool      `json:"working"`
	Reason        string    `json:"reason"`
	Connected     bool      `json:"connected"`
	LastError     string    `json:"lastError,omitempty"`
	LastContactAt time.Time `json:"lastContactAt,omitempty"`

	ChecksToday int   `json:"checksToday"`
	BytesToday  int64 `json:"bytesToday"`
	ChecksTotal int64 `json:"checksTotal"`
	BytesTotal  int64 `json:"bytesTotal"`

	LimitPerMinute int `json:"limitPerMinute"`
	HardLimit      int `json:"hardLimit"`
}

const recentLogSize = 50

type Supervisor struct {
	api      *client.Client
	identity *identity.Identity
	store    *settings.Store
	limiter  *guardrails.RateLimiter
	cooldown *guardrails.Cooldown
	logf     func(string, ...any)

	mu       sync.RWMutex
	state    State
	recent   []CheckLogEntry
	dayStamp string

	wake     chan struct{}
	onChange func(State)
}

func New(api *client.Client, id *identity.Identity, store *settings.Store, logf func(string, ...any)) *Supervisor {
	s := &Supervisor{
		api:      api,
		identity: id,
		store:    store,
		limiter:  guardrails.NewRateLimiter(),
		cooldown: guardrails.NewCooldown(),
		logf:     logf,
		wake:     make(chan struct{}, 1),
		dayStamp: time.Now().Format("2006-01-02"),
	}
	s.limiter.SetLimit(store.Get().MaxChecksPerMinute)
	s.state.HardLimit = guardrails.MaxChecksPerMinute
	s.state.LimitPerMinute = s.limiter.Limit()
	s.refreshWorking()
	return s
}

// OnChange регистрирует наблюдателя (иконка в трее меняет вид по этому сигналу).
func (s *Supervisor) OnChange(fn func(State)) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

func (s *Supervisor) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Supervisor) Recent() []CheckLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CheckLogEntry, len(s.recent))
	copy(out, s.recent)
	return out
}

// ApplySettings подхватывает изменения из интерфейса без перезапуска.
func (s *Supervisor) ApplySettings(next settings.Settings) {
	s.limiter.SetLimit(next.MaxChecksPerMinute)
	s.mu.Lock()
	s.state.LimitPerMinute = s.limiter.Limit()
	s.mu.Unlock()
	s.refreshWorking()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Supervisor) refreshWorking() {
	current := s.store.Get()
	working := current.Working()
	reason := "running"
	if !current.Active {
		reason = "stopped_by_user"
	} else if !current.PausedUntil.IsZero() {
		reason = "paused_until"
	}

	s.mu.Lock()
	changed := s.state.Working != working || s.state.Reason != reason
	s.state.Working = working
	s.state.Reason = reason
	state := s.state
	notify := s.onChange
	s.mu.Unlock()

	if changed && notify != nil {
		notify(state)
	}
}

func (s *Supervisor) Run(ctx context.Context) {
	failures := 0
	for ctx.Err() == nil {
		s.rolloverDay()
		s.refreshWorking()

		if !s.State().Working {
			// На паузе сервер не опрашивается вообще; просыпаемся по сигналу от
			// интерфейса или по таймеру, чтобы вовремя заметить конец паузы.
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
			case <-time.After(10 * time.Second):
			}
			continue
		}

		tasks, err := s.api.Poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			s.setConnection(false, err.Error())
			backoff := time.Duration(min(30, 1<<min(failures, 5))) * time.Second
			s.logf("poll failed (%v) — retrying in %s", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		failures = 0
		s.setConnection(true, "")

		if len(tasks) == 0 {
			continue
		}
		s.executeBatch(ctx, tasks)
	}
}

func (s *Supervisor) executeBatch(ctx context.Context, tasks []protocol.Task) {
	tunnelHint := vpnhint.LikelyBehindTunnel()
	results := make([]map[string]any, 0, len(tasks))

	for _, task := range tasks {
		// Настройки могли поменяться прямо посреди пачки.
		if !s.store.Get().Working() {
			break
		}
		result, ok := s.executeOne(ctx, task, tunnelHint)
		if ok {
			results = append(results, result)
		}
	}

	if len(results) > 0 {
		if err := s.api.SubmitResults(ctx, results); err != nil && ctx.Err() == nil {
			s.logf("submitting results failed: %v", err)
		}
	}
}

func (s *Supervisor) executeOne(ctx context.Context, task protocol.Task, tunnelHint bool) (map[string]any, bool) {
	if !protocol.Verify(s.identity.ServerKey, task.SignedPayload(), task.Sig) {
		s.logf("dropping task %s: signature does not verify against the pinned server key", task.ID)
		return nil, false
	}
	spec := guardrails.TaskSpec{
		Domain: task.Domain, Port: task.Port, Scheme: task.Scheme,
		Path: task.Path, Method: task.Method, IssuedAt: time.UnixMilli(task.IssuedAt),
	}
	if err := guardrails.ValidateTask(spec); err != nil {
		s.logf("dropping task %s: %v", task.ID, err)
		return nil, false
	}
	if !s.limiter.Allow() {
		s.logf("dropping task %s: rate limit (%d/min) reached", task.ID, s.limiter.Limit())
		return nil, false
	}
	if !s.cooldown.Allow(task.Domain) {
		s.logf("dropping task %s: %s checked less than %s ago", task.ID, task.Domain, guardrails.PerTargetCooldown)
		return nil, false
	}

	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	outcome := checker.Run(checkCtx, checker.Target{
		Domain: task.Domain, Port: task.Port, Scheme: task.Scheme,
		Path: task.Path, Method: task.Method,
	})

	total := outcome.DNSMs + outcome.TCPMs + outcome.TLSMs + outcome.HTTPMs
	s.record(CheckLogEntry{
		At: time.Now(), Kind: task.Kind, Domain: task.Domain, Stage: outcome.Stage,
		Status: outcome.HTTPStatus, Error: outcome.ErrorCode, Ms: total,
	}, outcome.BytesIn+outcome.BytesOut)

	return map[string]any{
		"taskId": task.ID, "monitorId": task.MonitorID, "kind": task.Kind,
		"stage": outcome.Stage, "errorCode": outcome.ErrorCode, "httpStatus": outcome.HTTPStatus,
		"dnsMs": outcome.DNSMs, "tcpMs": outcome.TCPMs, "tlsMs": outcome.TLSMs, "httpMs": outcome.HTTPMs,
		"resolvedIp": outcome.ResolvedIP, "selfReportedVpnIface": tunnelHint,
	}, true
}

func (s *Supervisor) record(entry CheckLogEntry, bytes int64) {
	s.mu.Lock()
	s.state.ChecksToday++
	s.state.ChecksTotal++
	s.state.BytesToday += bytes
	s.state.BytesTotal += bytes
	s.recent = append([]CheckLogEntry{entry}, s.recent...)
	if len(s.recent) > recentLogSize {
		s.recent = s.recent[:recentLogSize]
	}
	s.mu.Unlock()
}

func (s *Supervisor) setConnection(connected bool, errText string) {
	s.mu.Lock()
	changed := s.state.Connected != connected
	s.state.Connected = connected
	s.state.LastError = errText
	if connected {
		s.state.LastContactAt = time.Now()
	}
	state := s.state
	notify := s.onChange
	s.mu.Unlock()
	if changed && notify != nil {
		notify(state)
	}
}

func (s *Supervisor) rolloverDay() {
	today := time.Now().Format("2006-01-02")
	s.mu.Lock()
	if s.dayStamp != today {
		s.dayStamp = today
		s.state.ChecksToday = 0
		s.state.BytesToday = 0
	}
	s.mu.Unlock()
}
