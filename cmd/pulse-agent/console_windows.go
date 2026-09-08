//go:build windows

package main

import (
	"os"
	"syscall"
)

// attachParentConsole подключает вывод к консоли, из которой запустили программу.
//
// Сборка идёт с -H windowsgui, то есть своей консоли у приложения нет — это
// нужно, чтобы у партнёра при запуске не выскакивало чёрное окно. Но тогда
// `pulse-agent -limits` и `-status`, запущенные из cmd, печатали бы в никуда.
// ATTACH_PARENT_PROCESS возвращает им вывод, ничего не показывая тем, кто
// запустил программу двойным кликом.
func attachParentConsole() {
	const attachParentProcess = ^uintptr(0) // (DWORD)-1

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	attach := kernel32.NewProc("AttachConsole")
	if ret, _, _ := attach.Call(attachParentProcess); ret == 0 {
		return // консоли-родителя нет: запуск из проводника
	}

	for _, target := range []struct {
		name string
		file **os.File
	}{
		{"CONOUT$", &os.Stdout},
		{"CONOUT$", &os.Stderr},
	} {
		handle, err := syscall.Open(target.name, syscall.O_RDWR, 0)
		if err != nil {
			continue
		}
		*target.file = os.NewFile(uintptr(handle), target.name)
	}
}
