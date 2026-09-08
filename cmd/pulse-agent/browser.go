package main

import (
	"os/exec"
	"runtime"
)

// openBrowser открывает окно настроек в браузере пользователя.
//
// Это единственное место во всём агенте, где запускается внешняя программа.
// Аргумент — только собственный локальный адрес агента или путь к его журналу,
// никогда не значение, пришедшее с сервера: иначе «открыть ссылку» превратится
// в способ выполнить на машине партнёра что угодно.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil && log != nil {
		log.Printf("could not open browser: %v", err)
	}
}
