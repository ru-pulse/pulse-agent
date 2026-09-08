// Package applog пишет журнал в файл.
//
// Под Windows приложение собирается без консоли, поэтому всё, что раньше
// печаталось на экран, обязано попадать в файл: иначе упавший агент просто
// исчезает, не оставив никаких следов, и разобраться в проблеме партнёра
// становится нечем.
package applog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxSize = 2 << 20 // 2 МБ, дальше — одна ротация

type Logger struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	console io.Writer
}

// New открывает журнал рядом с настройками. console может быть nil — так и
// происходит в сборке без консоли.
func New(path string, console io.Writer) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	l := &Logger{path: path, console: console}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.file = file
	return nil
}

func (l *Logger) Printf(format string, args ...any) {
	line := fmt.Sprintf("%s  %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.console != nil {
		_, _ = io.WriteString(l.console, line)
	}
	if l.file == nil {
		return
	}
	if info, err := l.file.Stat(); err == nil && info.Size() > maxSize {
		_ = l.file.Close()
		_ = os.Rename(l.path, l.path+".1")
		if err := l.open(); err != nil {
			return
		}
	}
	_, _ = l.file.WriteString(line)
}

func (l *Logger) Path() string { return l.path }

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}
