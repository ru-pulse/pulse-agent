// Package settings хранит пользовательские настройки агента рядом с его
// идентичностью, в домашней папке пользователя.
//
// Главное правило этого пакета: настройки могут только ОСЛАБЛЯТЬ работу агента
// относительно зашитых ограничений, никогда не усиливать. Партнёр вправе
// сказать «используй мою машину поменьше»; ни он, ни тем более сервер не
// должны иметь возможности сказать «побольше».
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ru-pulse/pulse-agent/internal/guardrails"
)

type Settings struct {
	// Active=false — агент не опрашивает сервер вообще. Через минуту сервер
	// сам перестанет считать его онлайн и раздавать ему задания.
	Active bool `json:"active"`

	// PausedUntil — временная пауза («не мешай два часа»). Ноль означает, что
	// временной паузы нет.
	PausedUntil time.Time `json:"pausedUntil,omitempty"`

	// MaxChecksPerMinute зажимается в [1, guardrails.MaxChecksPerMinute].
	// Значение выше потолка молча опускается до потолка: константа в бинарнике
	// остаётся единственным источником истины о верхней границе.
	MaxChecksPerMinute int `json:"maxChecksPerMinute"`

	// City — необязательная метка для оператора, не влияет ни на что кроме
	// отображения.
	City string `json:"city,omitempty"`

	// Autostart отражает желаемое состояние автозапуска; фактическую установку
	// делает платформенный код.
	Autostart bool `json:"autostart"`
}

func Defaults() Settings {
	return Settings{
		Active:             true,
		MaxChecksPerMinute: guardrails.MaxChecksPerMinute,
		Autostart:          false,
	}
}

// Clamp приводит настройки к допустимым значениям. Вызывается и при загрузке
// (файл мог быть отредактирован руками), и при сохранении из интерфейса.
func (s *Settings) Clamp() {
	if s.MaxChecksPerMinute < 1 {
		s.MaxChecksPerMinute = 1
	}
	if s.MaxChecksPerMinute > guardrails.MaxChecksPerMinute {
		s.MaxChecksPerMinute = guardrails.MaxChecksPerMinute
	}
	if len(s.City) > 100 {
		s.City = s.City[:100]
	}
	// Пауза в прошлом ничего не значит.
	if !s.PausedUntil.IsZero() && time.Now().After(s.PausedUntil) {
		s.PausedUntil = time.Time{}
	}
}

// Working сообщает, должен ли агент прямо сейчас брать задания.
func (s Settings) Working() bool {
	if !s.Active {
		return false
	}
	return s.PausedUntil.IsZero() || time.Now().After(s.PausedUntil)
}

// Store — потокобезопасный доступ к файлу настроек.
type Store struct {
	mu      sync.RWMutex
	path    string
	current Settings
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pulse-agent", "settings.json"), nil
}

func Load(path string) (*Store, error) {
	store := &Store{path: path, current: Defaults()}

	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := store.save(); err != nil {
			return nil, err
		}
		return store, nil
	}

	var loaded Settings
	if err := json.Unmarshal(raw, &loaded); err != nil {
		// Испорченный файл не должен мешать агенту работать: откатываемся на
		// значения по умолчанию и перезаписываем.
		loaded = Defaults()
	}
	loaded.Clamp()
	store.current = loaded
	return store, nil
}

func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Update применяет изменения через функцию и сохраняет результат.
func (s *Store) Update(mutate func(*Settings)) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.current
	mutate(&next)
	next.Clamp()
	s.current = next
	if err := s.save(); err != nil {
		return next, err
	}
	return next, nil
}

// save пишет через временный файл: обрыв питания на записи не должен оставить
// пользователя с обрезанным JSON вместо настроек.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.current, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("сохранение настроек: %w", err)
	}
	return nil
}

func (s *Store) Path() string { return s.path }
