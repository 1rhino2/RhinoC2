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
