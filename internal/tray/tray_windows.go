//go:build windows

package tray

// Иконка в области уведомлений через Win32 напрямую.
//
// Почему не библиотека: весь смысл этого агента в том, что его код можно
// прочитать целиком и убедиться, что он не делает лишнего. Готовая обёртка над
// systray добавила бы десятки тысяч строк чужого кода в цепочку доверия ради
// одной иконки. Здесь вызовы shell32/user32 сделаны через syscall из
// стандартной библиотеки: кода больше, читать — меньше.
//
// Требование Win32: окно и цикл сообщений должны жить на одном потоке, поэтому
// Run захватывает поток через runtime.LockOSThread и блокируется до выхода.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassEx     = user32.NewProc("RegisterClassExW")
	procCreateWindowEx      = user32.NewProc("CreateWindowExW")
	procDefWindowProc       = user32.NewProc("DefWindowProcW")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procPostMessage         = user32.NewProc("PostMessageW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procAppendMenu          = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procLoadImage           = user32.NewProc("LoadImageW")
	procDestroyIcon         = user32.NewProc("DestroyIcon")
	procLoadIcon            = user32.NewProc("LoadIconW")
	procLoadCursor          = user32.NewProc("LoadCursorW")

	procShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")

	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmCommand      = 0x0111
	wmUser         = 0x0400
	wmTrayCallback = wmUser + 1
	wmAppUpdate    = wmUser + 2
	wmAppQuit      = wmUser + 3

	wmLButtonUp = 0x0202
	wmRButtonUp = 0x0205

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	imageIcon      = 1
	lrLoadFromFile = 0x00000010
	lrDefaultSize  = 0x00000040

	mfString    = 0x00000000
	mfSeparator = 0x00000800

	tpmLeftAlign   = 0x0000
	tpmRightButton = 0x0002

	idOpenSettings = 1001
	idToggle       = 1002
	idOpenLog      = 1003
	idQuit         = 1004

	cwUseDefault = ^uintptr(0x7FFFFFFF) // 0x80000000
)

type notifyIconData struct {
	CbSize           uint32
	HWnd             syscall.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            syscall.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     syscall.Handle
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type point struct{ X, Y int32 }

type msg struct {
	HWnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type windowsTray struct {
	hwnd    syscall.Handle
	opts    Options
	mu      sync.Mutex
	icons   map[Status]syscall.Handle
	current Status
	tooltip string
	pending struct {
		status  Status
		tooltip string
		set     bool
	}
}

var active *windowsTray

// Run поднимает иконку и возвращает управление вызывающему.
//
// Окно и цикл сообщений живут на ОДНОМ выделенном потоке: Win32 доставляет
// сообщения окна только тому потоку, который его создал, поэтому поток
// захватывается через LockOSThread внутри той же горутины, где вызывается
// CreateWindowEx. Разнести эти две вещи по разным горутинам — значит получить
// иконку, которая появляется, но не реагирует ни на что.
func Run(opts Options) (Controller, error) {
	t := &windowsTray{opts: opts, icons: map[Status]syscall.Handle{}}
	ready := make(chan error, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := t.init(); err != nil {
			ready <- err
			return
		}
		ready <- nil
		t.messageLoop()
	}()

	if err := <-ready; err != nil {
		return nil, err
	}
	return t, nil
}

func (t *windowsTray) init() error {
	t.loadIcons()

	instance, _, _ := procGetModuleHandle.Call(0)
	className := syscall.StringToUTF16Ptr("PulseAgentTrayWindow")

	cursor, _, _ := procLoadCursor.Call(0, 32512) // IDC_ARROW
	class := wndClassEx{
		Style:         0,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     syscall.Handle(instance),
		HCursor:       syscall.Handle(cursor),
		LpszClassName: className,
	}
	class.CbSize = uint32(unsafe.Sizeof(class))
	if ret, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&class))); ret == 0 {
		return fmt.Errorf("RegisterClassEx: %w", err)
	}

	hwnd, _, err := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Пульс Рунета"))),
		0,
		cwUseDefault, cwUseDefault, 0, 0,
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %w", err)
	}
	t.hwnd = syscall.Handle(hwnd)
	active = t

	return t.notify(nimAdd, StatusStopped, t.opts.Tooltip)
}

func (t *windowsTray) messageLoop() {
	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 { // 0 — WM_QUIT, -1 — ошибка
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// loadIcons берёт .ico рядом с исполняемым файлом. Если файлов нет, иконка
// будет системной по умолчанию: отсутствие картинки не повод не запускаться.
func (t *windowsTray) loadIcons() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	for status, name := range map[Status]string{
		StatusWorking:   "tray-active.ico",
		StatusStopped:   "tray-paused.ico",
		StatusAttention: "tray-attention.ico",
	} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		handle, _, _ := procLoadImage.Call(
			0,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(path))),
			imageIcon, 0, 0,
			lrLoadFromFile|lrDefaultSize,
		)
		if handle != 0 {
			t.icons[status] = syscall.Handle(handle)
		}
	}
}

func (t *windowsTray) iconFor(status Status) syscall.Handle {
	if handle, ok := t.icons[status]; ok {
		return handle
	}
	handle, _, _ := procLoadIcon.Call(0, 32512) // IDI_APPLICATION
	return syscall.Handle(handle)
}

func (t *windowsTray) notify(action uint32, status Status, tooltip string) error {
	data := notifyIconData{
		HWnd:             t.hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: wmTrayCallback,
		HIcon:            t.iconFor(status),
	}
	data.CbSize = uint32(unsafe.Sizeof(data))
	copyUTF16(data.SzTip[:], tooltip)

	ret, _, err := procShellNotifyIcon.Call(uintptr(action), uintptr(unsafe.Pointer(&data)))
	if ret == 0 && action != nimDelete {
		return fmt.Errorf("Shell_NotifyIcon: %w", err)
	}
	return nil
}

// SetStatus вызывается из других горутин, поэтому сама работа с окном
// выполняется в потоке цикла сообщений: Win32 не прощает обращения к окну с
// чужого потока.
func (t *windowsTray) SetStatus(status Status, tooltip string) {
	t.mu.Lock()
	t.pending.status = status
	t.pending.tooltip = tooltip
	t.pending.set = true
	t.mu.Unlock()
	procPostMessage.Call(uintptr(t.hwnd), wmAppUpdate, 0, 0)
}

func (t *windowsTray) applyPending() {
	t.mu.Lock()
	if !t.pending.set {
		t.mu.Unlock()
		return
	}
	status, tooltip := t.pending.status, t.pending.tooltip
	t.pending.set = false
	t.current, t.tooltip = status, tooltip
	t.mu.Unlock()
	_ = t.notify(nimModify, status, tooltip)
}

// Stop только просит поток окна закрыться: DestroyWindow с чужого потока
// Win32 игнорирует, оставляя иконку висеть в трее после выхода программы.
func (t *windowsTray) Stop() {
	procPostMessage.Call(uintptr(t.hwnd), wmAppQuit, 0, 0)
}

// teardown выполняется уже на потоке окна.
func (t *windowsTray) teardown() {
	_ = t.notify(nimDelete, t.current, "")
	for _, handle := range t.icons {
		procDestroyIcon.Call(uintptr(handle))
	}
	procDestroyWindow.Call(uintptr(t.hwnd))
	procPostQuitMessage.Call(0)
}

func (t *windowsTray) showMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	toggleLabel := "Запустить"
	if t.current == StatusWorking || t.current == StatusAttention {
		toggleLabel = "Остановить"
	}
	appendItem(menu, idToggle, toggleLabel)
	appendItem(menu, idOpenSettings, "Настройки…")
	appendItem(menu, idOpenLog, "Открыть журнал")
	procAppendMenu.Call(menu, mfSeparator, 0, 0)
	appendItem(menu, idQuit, "Выход")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// Без этого меню не закроется по клику мимо него — известная особенность
	// Win32 для меню, вызванных из области уведомлений.
	procSetForegroundWindow.Call(uintptr(t.hwnd))
	procTrackPopupMenu.Call(
		menu, tpmLeftAlign|tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0,
	)
}

func appendItem(menu uintptr, id uintptr, label string) {
	procAppendMenu.Call(menu, mfString, id, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(label))))
}

func wndProc(hwnd syscall.Handle, message uint32, wparam, lparam uintptr) uintptr {
	t := active
	if t == nil {
		ret, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wparam, lparam)
		return ret
	}

	switch message {
	case wmTrayCallback:
		switch uint32(lparam) {
		case wmLButtonUp:
			if t.opts.OnOpenSettings != nil {
				go t.opts.OnOpenSettings()
			}
		case wmRButtonUp:
			t.showMenu()
		}
		return 0

	case wmAppUpdate:
		t.applyPending()
		return 0

	case wmAppQuit:
		t.teardown()
		return 0

	case wmCommand:
		switch uintptr(uint16(wparam)) {
		case idToggle:
			if t.opts.OnToggle != nil {
				go t.opts.OnToggle()
			}
		case idOpenSettings:
			if t.opts.OnOpenSettings != nil {
				go t.opts.OnOpenSettings()
			}
		case idOpenLog:
			if t.opts.OnOpenLog != nil {
				go t.opts.OnOpenLog()
			}
		case idQuit:
			if t.opts.OnQuit != nil {
				go t.opts.OnQuit()
			}
		}
		return 0

	case wmClose, wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wparam, lparam)
	return ret
}

func copyUTF16(dst []uint16, s string) {
	encoded, err := syscall.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(encoded) > len(dst) {
		encoded = encoded[:len(dst)-1]
		encoded = append(encoded, 0)
	}
	copy(dst, encoded)
}
