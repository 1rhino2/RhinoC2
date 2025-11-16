package commands

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

type Commander struct {
	shell string
	args  []string
}

func NewCommander() *Commander {
	if runtime.GOOS == "windows" {
		return &Commander{
			shell: "powershell.exe",
			args:  []string{"-NoProfile", "-NonInteractive", "-Command"},
		}
	}
	return &Commander{
		shell: "/bin/sh",
		args:  []string{"-c"},
	}
}

func (c *Commander) Execute(command string) (string, error) {
	args := append(c.args, command)
	cmd := exec.Command(c.shell, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("execution failed: %v", err)
	}
	return string(output), nil
}

func (c *Commander) ExecuteWithTimeout(command string, timeoutSec int) (string, error) {
	args := append(c.args, command)
	cmd := exec.Command(c.shell, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("execution failed: %v", err)
	}
	return string(output), nil
}

func (c *Commander) StartBackground(command string) (*exec.Cmd, error) {
	args := append(c.args, command)
	cmd := exec.Command(c.shell, args...)
	err := cmd.Start()
	return cmd, err
}

func GetSystemInfo() map[string]string {
	info := make(map[string]string)
	info["os"] = runtime.GOOS
	info["arch"] = runtime.GOARCH
	info["numcpu"] = fmt.Sprintf("%d", runtime.NumCPU())

	if runtime.GOOS == "windows" {
		if out, err := exec.Command("powershell", "-Command", "Get-ComputerInfo | Select-Object -Property OsName,OsVersion,OsArchitecture | ConvertTo-Json").Output(); err == nil {
			info["details"] = string(out)
		}
	}

	return info
}

func GetProcessList() (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-Command", "Get-Process | Select-Object Id,Name,Path,CPU | ConvertTo-Json")
	} else {
		cmd = exec.Command("ps", "aux")
	}

	output, err := cmd.Output()
	return string(output), err
}

func KillProcess(pid string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("taskkill", "/F", "/PID", pid)
	} else {
		cmd = exec.Command("kill", "-9", pid)
	}
	return cmd.Run()
}

func IsAdmin() bool {
	if runtime.GOOS != "windows" {
		return os.Geteuid() == 0
	}

	shell32 := syscall.NewLazyDLL("shell32.dll")
	isUserAnAdmin := shell32.NewProc("IsUserAnAdmin")
	ret, _, _ := isUserAnAdmin.Call()
	return ret != 0
}

func GetProcessIntegrityLevel() string {
	if runtime.GOOS != "windows" {
		if os.Geteuid() == 0 {
			return "high"
		}
		return "medium"
	}

	cmd := exec.Command("powershell", "-Command", "whoami /groups | findstr /C:\"Mandatory Label\"")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	result := strings.ToLower(string(output))
	if strings.Contains(result, "high") || strings.Contains(result, "system") {
		return "high"
	} else if strings.Contains(result, "medium") {
		return "medium"
	} else if strings.Contains(result, "low") {
		return "low"
	}
	return "unknown"
}

func GetPPID() int {
	if runtime.GOOS != "windows" {
		return os.Getppid()
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcessId := kernel32.NewProc("GetCurrentProcessId")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")
	closeHandle := kernel32.NewProc("CloseHandle")

	const TH32CS_SNAPPROCESS = 0x00000002
	type PROCESSENTRY32 struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [260]uint16
	}

	currentPID, _, _ := getCurrentProcessId.Call()
	snapshot, _, _ := createToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == 0 {
		return 0
	}
	defer closeHandle.Call(snapshot)

	var pe PROCESSENTRY32
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := process32First.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return 0
	}

	for {
		if pe.th32ProcessID == uint32(currentPID) {
			return int(pe.th32ParentProcessID)
		}
		ret, _, _ := process32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	return 0
}
