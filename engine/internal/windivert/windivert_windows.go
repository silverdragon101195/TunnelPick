// Package windivert is a minimal, cgo-free binding to WinDivert.dll (2.2.x).
package windivert

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

// Layer selects which WinDivert layer a handle is opened on.
type Layer uint32

const (
	LayerNetwork Layer = 0
	LayerFlow    Layer = 2
	LayerSocket  Layer = 3
)

const (
	FlagSniff     uint64 = 0x0001
	FlagRecvOnly  uint64 = 0x0004
	FlagSendOnly  uint64 = 0x0008
	FlagNoInstall uint64 = 0x0010
)

// Queue parameters (WINDIVERT_PARAM_*).
const (
	ParamQueueLength = 0
	ParamQueueTime   = 1
	ParamQueueSize   = 2
	ParamVersionMaj  = 3
	ParamVersionMin  = 4
)

// Address mirrors WINDIVERT_ADDRESS (80 bytes). Bit-fields are exposed through methods.
type Address struct {
	Timestamp int64
	bits      uint32
	_         uint32
	IfIdx     uint32 // Network layer: interface index (shares storage with the union)
	SubIfIdx  uint32
	_         [56]byte
}

const (
	bitOutbound = 1 << 17
	bitLoopback = 1 << 18
	bitIPv6     = 1 << 20
)

func (a *Address) Outbound() bool { return a.bits&bitOutbound != 0 }
func (a *Address) Loopback() bool { return a.bits&bitLoopback != 0 }
func (a *Address) IPv6() bool     { return a.bits&bitIPv6 != 0 }

func (a *Address) SetOutbound(v bool) {
	if v {
		a.bits |= bitOutbound
	} else {
		a.bits &^= bitOutbound
	}
}

var (
	loadOnce sync.Once
	loadErr  error
	dll      *syscall.DLL

	procOpen       *syscall.Proc
	procRecv       *syscall.Proc
	procSend       *syscall.Proc
	procClose      *syscall.Proc
	procShutdown   *syscall.Proc
	procSetParam   *syscall.Proc
	procGetParam   *syscall.Proc
	procChecksums  *syscall.Proc
	invalidHandle  = ^uintptr(0)
	errNotAdmin    = errors.New("administrator rights are required to open WinDivert")
	errNoDriverSys = errors.New("WinDivert64.sys not found next to WinDivert.dll")
)

// Load resolves WinDivert.dll from dir (the directory holding the engine executable when empty).
// WinDivert64.sys must sit in the same directory.
func Load(dir string) error {
	loadOnce.Do(func() {
		if dir == "" {
			exe, err := os.Executable()
			if err != nil {
				loadErr = err
				return
			}
			dir = filepath.Dir(exe)
		}
		if _, err := os.Stat(filepath.Join(dir, "WinDivert64.sys")); err != nil {
			loadErr = errNoDriverSys
			return
		}
		d, err := syscall.LoadDLL(filepath.Join(dir, "WinDivert.dll"))
		if err != nil {
			loadErr = fmt.Errorf("load WinDivert.dll: %w", err)
			return
		}
		dll = d
		for name, dst := range map[string]**syscall.Proc{
			"WinDivertOpen":                &procOpen,
			"WinDivertRecv":                &procRecv,
			"WinDivertSend":                &procSend,
			"WinDivertClose":               &procClose,
			"WinDivertShutdown":            &procShutdown,
			"WinDivertSetParam":            &procSetParam,
			"WinDivertGetParam":            &procGetParam,
			"WinDivertHelperCalcChecksums": &procChecksums,
		} {
			p, err := d.FindProc(name)
			if err != nil {
				loadErr = err
				return
			}
			*dst = p
		}
	})
	return loadErr
}

// Handle is an open WinDivert handle.
type Handle struct{ h uintptr }

// Open opens a handle. The driver is installed on first use (needs administrator rights).
func Open(filter string, layer Layer, priority int16, flags uint64) (*Handle, error) {
	if err := Load(""); err != nil {
		return nil, err
	}
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	h, _, e := procOpen.Call(uintptr(unsafe.Pointer(f)), uintptr(layer), uintptr(uint16(priority)), uintptr(flags))
	if h == invalidHandle {
		if errno, ok := e.(syscall.Errno); ok {
			switch errno {
			case 5:
				return nil, errNotAdmin
			case 577:
				return nil, fmt.Errorf("windows rejected the WinDivert driver signature (ERROR_INVALID_IMAGE_HASH): %w", errno)
			case 1275:
				return nil, fmt.Errorf("the WinDivert driver is blocked by a Windows policy such as HVCI or the vulnerable driver blocklist (ERROR_DRIVER_BLOCKED): %w", errno)
			}
		}
		return nil, fmt.Errorf("WinDivertOpen(%q): %w", filter, e)
	}
	return &Handle{h: h}, nil
}

// Recv blocks until a packet arrives.
func (h *Handle) Recv(buf []byte, addr *Address) (int, error) {
	var n uint32
	r, _, e := procRecv.Call(h.h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return 0, e
	}
	return int(n), nil
}

// Send injects a packet.
func (h *Handle) Send(pkt []byte, addr *Address) error {
	var n uint32
	r, _, e := procSend.Call(h.h, uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return e
	}
	return nil
}

// Shutdown makes pending and future Recv calls fail so a reader loop can exit.
func (h *Handle) Shutdown() { procShutdown.Call(h.h, 0x3) }

func (h *Handle) Close() { procClose.Call(h.h) }

func (h *Handle) SetParam(param uint32, value uint64) error {
	r, _, e := procSetParam.Call(h.h, uintptr(param), uintptr(value))
	if r == 0 {
		return e
	}
	return nil
}

func (h *Handle) GetParam(param uint32) (uint64, error) {
	var v uint64
	r, _, e := procGetParam.Call(h.h, uintptr(param), uintptr(unsafe.Pointer(&v)))
	if r == 0 {
		return 0, e
	}
	return v, nil
}

// CalcChecksums recomputes the IP, TCP and UDP checksums of pkt in place.
func CalcChecksums(pkt []byte, addr *Address) {
	procChecksums.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(addr)), 0)
}
