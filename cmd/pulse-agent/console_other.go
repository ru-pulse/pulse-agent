//go:build !windows

package main

// На остальных платформах консоль есть всегда.
func attachParentConsole() {}
