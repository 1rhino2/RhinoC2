package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type PersistenceHandler struct {
	execPath string
}

func NewPersistenceHandler() (*PersistenceHandler, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &PersistenceHandler{
		execPath: execPath,
	}, nil
}

func (p *PersistenceHandler) InstallRegistry(name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry persistence only works on Windows")
	}

	cmd := exec.Command("reg", "add",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name,
		"/t", "REG_SZ",
		"/d", p.execPath,
		"/f")

	return cmd.Run()
}

func (p *PersistenceHandler) RemoveRegistry(name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry persistence only works on Windows")
	}

	cmd := exec.Command("reg", "delete",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name,
		"/f")

	return cmd.Run()
}

func (p *PersistenceHandler) InstallStartupFolder(name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("startup folder persistence only works on Windows")
	}

	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	linkPath := filepath.Join(startupPath, name+".lnk")

