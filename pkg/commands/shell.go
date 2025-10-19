package commands

import (
	"fmt"
	"os/exec"
	"runtime"
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
