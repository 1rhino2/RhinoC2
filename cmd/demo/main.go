package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Message struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"`
}

type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Args    string `json:"args"`
}

type TaskResult struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Result  string `json:"result"`
	Error   string `json:"error"`
}

type DemoAgent struct {
	id       string
	conn     *websocket.Conn
	hostname string
	username string
	tasks    chan Task
}

func generateID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return strings.ToUpper(fmt.Sprintf("%x", b))
}

func getHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "DEMO-PC-" + fmt.Sprintf("%04d", rand.Intn(9999))
	}
	return host
}

func getUsername() string {
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = "demo_user"
	}
	return user
}

func getLocalIP() string {
	return fmt.Sprintf("192.168.1.%d", 100+rand.Intn(150))
}

func isAdmin() bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("net", "session")
		err := cmd.Run()
		return err == nil
	}
	return os.Geteuid() == 0
}

func getIntegrity() string {
	if isAdmin() {
		return "high"
	}
	return "medium"
}

func newDemoAgent(serverURL string) (*DemoAgent, error) {
	conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		return nil, err
	}

	agent := &DemoAgent{
		id:       generateID(),
		conn:     conn,
		hostname: getHostname(),
		username: getUsername(),
		tasks:    make(chan Task, 10),
	}

	return agent, nil
}

func (a *DemoAgent) register() error {
	checkin := map[string]interface{}{
		"id":        a.id,
		"hostname":  a.hostname,
		"username":  a.username,
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"ip":        getLocalIP(),
		"pid":       os.Getpid(),
		"ppid":      os.Getppid(),
		"is_admin":  isAdmin(),
		"integrity": getIntegrity(),
		"is_demo":   true,
	}

	return a.conn.WriteJSON(checkin)
}

func (a *DemoAgent) listen() {
	for {
		var task Task
		err := a.conn.ReadJSON(&task)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		log.Printf("Received task: %s %s", task.Command, task.ID[:8])
		a.tasks <- task
	}
}

func (a *DemoAgent) processTasks() {
	for task := range a.tasks {
		log.Printf("Processing task: %s", task.Command)
		result := a.executeTask(task)

		response := map[string]interface{}{
			"task_id": task.ID,
			"result":  result.Result,
		}

		err := a.conn.WriteJSON(response)
		if err != nil {
			log.Printf("Failed to send result: %v", err)
		}
	}
}

func (a *DemoAgent) executeTask(task Task) TaskResult {
	result := TaskResult{
		ID:      task.ID,
		Command: task.Command,
	}

	time.Sleep(time.Duration(200+rand.Intn(800)) * time.Millisecond)

	switch task.Command {
	case "shell":
		result.Result = a.mockShell(task.Args)
	case "pwd":
		if runtime.GOOS == "windows" {
			result.Result = "C:\\Users\\" + a.username + "\\Desktop"
		} else {
			result.Result = "/home/" + a.username
		}
	case "sysinfo":
		result.Result = a.mockSysinfo()
	case "ps":
		result.Result = a.mockProcessList()
	case "ls":
		result.Result = a.mockFileList(task.Args)
	case "net_interfaces":
		result.Result = a.mockNetworkInfo()
	case "whoami":
		result.Result = a.username
	case "hostname":
		result.Result = a.hostname
	case "ipconfig", "ifconfig":
		result.Result = a.mockIPConfig()
	case "check_evasion":
		result.Result = a.mockEvasionCheck()
	case "harvest_creds":
		result.Result = a.mockCredHarvest()
	case "persist":
		result.Result = "Persistence installed: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate"
	case "unpersist":
		result.Result = "Persistence removed successfully"
	case "screenshot":
		result.Result = "Screenshot captured (mock)"
	case "clipboard":
		result.Result = a.mockClipboard()
	case "sleep":
		result.Result = fmt.Sprintf("Sleep interval set to %s seconds", task.Args)
	case "exit":
		result.Result = "Agent terminating..."
		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
	default:
		result.Error = fmt.Sprintf("Unknown command: %s", task.Command)
	}

	return result
}

func (a *DemoAgent) mockShell(cmd string) string {
	responses := map[string]string{
		"whoami":   a.username,
		"hostname": a.hostname,
		"echo":     strings.TrimPrefix(cmd, "echo "),
		"dir":      "Volume in drive C has no label.\nDirectory of C:\\Users\\" + a.username + "\\Desktop\n\n11/16/2025  01:45 PM    <DIR>          .\n11/16/2025  01:45 PM    <DIR>          ..\n11/15/2025  03:22 PM            12,456 document.pdf\n11/14/2025  09:18 AM             5,932 notes.txt\n               2 File(s)         18,388 bytes\n               2 Dir(s)  458,234,880,000 bytes free",
	}

	for key, resp := range responses {
		if strings.Contains(strings.ToLower(cmd), key) {
			return resp
		}
	}

	return fmt.Sprintf("'%s' executed successfully (mock)", cmd)
}

func (a *DemoAgent) mockSysinfo() string {
	osVersion := map[string]string{
		"windows": "Windows 10 Pro (Build 19045)",
		"linux":   "Ubuntu 22.04.3 LTS",
		"darwin":  "macOS Sonoma 14.1",
	}[runtime.GOOS]

	processors := []string{"Intel Core i7-9700K", "AMD Ryzen 7 5800X", "Intel Core i5-11400"}
	cpu := processors[rand.Intn(len(processors))]
	ramGB := []int{8, 16, 32}[rand.Intn(3)]

	return fmt.Sprintf(`System Information:
OS: %s
Architecture: %s
Processor: %s @ 3.6GHz
RAM: %dGB
Hostname: %s
Username: %s
Domain: WORKGROUP
Uptime: %d days, %d hours`,
		osVersion, runtime.GOARCH, cpu, ramGB, a.hostname, a.username,
		rand.Intn(30), rand.Intn(24))
}

func (a *DemoAgent) mockProcessList() string {
	processes := []string{
		"svchost.exe         1234    2.5MB   Services and Controller app",
		"explorer.exe        2456    45.2MB  Windows Explorer",
		"chrome.exe          3789    256.8MB Google Chrome",
		"code.exe            4123    189.3MB Visual Studio Code",
		"discord.exe         5678    98.7MB  Discord",
		"steam.exe           6789    45.1MB  Steam Client",
		"notepad.exe         7890    1.2MB   Notepad",
		"taskmgr.exe         8901    12.4MB  Task Manager",
	}

	result := "PID     Memory  Name\n"
	result += "------- ------- ----\n"
	for _, proc := range processes {
		result += proc + "\n"
	}
	return result
}

func (a *DemoAgent) mockFileList(path string) string {
	files := []string{
		"Documents/",
		"Downloads/",
		"Pictures/",
		"project_report.docx  (245 KB)",
		"budget_2025.xlsx     (89 KB)",
		"vacation_photo.jpg   (3.2 MB)",
		"meeting_notes.txt    (12 KB)",
		".env                 (2 KB)",
	}

	if path == "" || path == "." {
		path = "C:\\Users\\" + a.username
	}

	result := fmt.Sprintf("Directory: %s\n\n", path)
	for _, file := range files {
		result += file + "\n"
	}
	return result
}

func (a *DemoAgent) mockNetworkInfo() string {
	return fmt.Sprintf(`Network Interfaces:

Ethernet0:
  IP: %s
  MAC: %02X:%02X:%02X:%02X:%02X:%02X
  Gateway: 192.168.1.1
  DNS: 8.8.8.8, 1.1.1.1
  Status: Up

WiFi0:
  IP: 192.168.1.%d
  MAC: %02X:%02X:%02X:%02X:%02X:%02X
  SSID: HomeNetwork_5G
  Status: Connected`,
		getLocalIP(),
		rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256),
		50+rand.Intn(50),
		rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func (a *DemoAgent) mockIPConfig() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`Windows IP Configuration

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix: lan
   IPv4 Address: %s
   Subnet Mask: 255.255.255.0
   Default Gateway: 192.168.1.1`, getLocalIP())
	}
	return fmt.Sprintf(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>
        inet %s  netmask 255.255.255.0  broadcast 192.168.1.255
        ether %02x:%02x:%02x:%02x:%02x:%02x`,
		getLocalIP(),
		rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func (a *DemoAgent) mockEvasionCheck() string {
	checks := []struct {
		name   string
		status string
	}{
		{"Virtual Machine", "Not Detected"},
		{"Debugger", "Not Present"},
		{"Sandbox Environment", "Clear"},
		{"Analysis Tools", "None Found"},
		{"AV/EDR Products", "Windows Defender (Active)"},
	}

	result := "Evasion Status Check:\n\n"
	for _, check := range checks {
		result += fmt.Sprintf("%-25s: %s\n", check.name, check.status)
	}
	return result
}

func (a *DemoAgent) mockCredHarvest() string {
	creds := []string{
		"[Chrome] gmail.com - user@email.com:********",
		"[Chrome] github.com - developer123:********",
		"[FileZilla] ftp.example.com - ftpuser:********",
		"[Outlook] user@company.com:********",
	}

	result := "Credential Harvest Results:\n\n"
	for _, cred := range creds {
		result += cred + "\n"
	}
	result += fmt.Sprintf("\nTotal: %d credentials found", len(creds))
	return result
}

func (a *DemoAgent) mockClipboard() string {
	clips := []string{
		"https://github.com/example/repository",
		"Meeting at 3 PM tomorrow",
		"sk_live_51abc123def456ghi789jkl",
		"192.168.1.254",
		"SELECT * FROM users WHERE id=1",
	}
	return clips[rand.Intn(len(clips))]
}

func (a *DemoAgent) heartbeat() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		heartbeat := map[string]interface{}{
			"heartbeat": true,
		}

		err := a.conn.WriteJSON(heartbeat)
		if err != nil {
			log.Printf("Heartbeat failed: %v", err)
			return
		}
		log.Printf("Heartbeat sent")
	}
}

func main() {
	serverURL := "ws://localhost:8443/api/agent"
	if len(os.Args) > 1 {
		serverURL = os.Args[1]
	}

	log.Printf("Demo agent starting...")
	log.Printf("Connecting to: %s", serverURL)

	agent, err := newDemoAgent(serverURL)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer agent.conn.Close()

	log.Printf("Connected with ID: %s", agent.id[:16])

	if err := agent.register(); err != nil {
		log.Fatalf("Registration failed: %v", err)
	}

	log.Printf("Registered as %s@%s", agent.username, agent.hostname)

	// send initial heartbeat to trigger task processing
	agent.conn.WriteJSON(map[string]interface{}{"heartbeat": true})

	go agent.listen()
	go agent.processTasks()
	go agent.heartbeat()

	select {}
}
