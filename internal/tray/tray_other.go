//go:build !windows

package tray

// Run на платформах без трея ничего не делает: агент остаётся консольным.
func Run(Options) (Controller, error) { return nil, ErrUnsupported }
