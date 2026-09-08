// Package tray — иконка в области уведомлений.
//
// Реализация есть только под Windows: там это единственный способ показать
// работающее фоновое приложение без окна. На остальных платформах Run сразу
// возвращает ErrUnsupported, и агент работает как обычная консольная программа.
package tray

import "errors"

// ErrUnsupported означает «на этой платформе трея нет», а не сбой.
var ErrUnsupported = errors.New("tray is not supported on this platform")

// Status определяет, какая иконка показывается.
type Status int

const (
	StatusStopped Status = iota
	StatusWorking
	StatusAttention // работает, но что-то требует внимания: нет привязки или связи
)

type Options struct {
	Tooltip        string
	OnOpenSettings func()
	OnToggle       func()
	OnOpenLog      func()
	OnQuit         func()
}

// Controller позволяет менять иконку и подсказку из работающего агента.
type Controller interface {
	SetStatus(Status, string)
	Stop()
}
