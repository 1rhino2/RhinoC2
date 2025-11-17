package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("RhinoC2 Configuration Generator")
	fmt.Println("================================")
	fmt.Println()

	var configType string
	fmt.Print("Generate config for [a]gent or [s]erver? (a/s): ")
	configType, _ = reader.ReadString('\n')
	configType = strings.ToLower(strings.TrimSpace(configType))

	if configType == "a" || configType == "agent" {
		generateAgentConfig(reader)
	} else if configType == "s" || configType == "server" {
		generateServerConfig(reader)
	} else {
		fmt.Println("Invalid selection. Use 'a' for agent or 's' for server.")
	}
}

func generateAgentConfig(reader *bufio.Reader) {
	fmt.Println("\nAgent Configuration")
	fmt.Println("-------------------")

	fmt.Print("Server Address (e.g., 192.168.1.100): ")
	serverAddr, _ := reader.ReadString('\n')
	serverAddr = strings.TrimSpace(serverAddr)

	fmt.Print("Server Port [8443]: ")
	serverPort, _ := reader.ReadString('\n')
	serverPort = strings.TrimSpace(serverPort)
	if serverPort == "" {
		serverPort = "8443"
	}

	fmt.Print("Encryption Key [RhinoC2SecretKey2025]: ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)
	if key == "" {
		key = "RhinoC2SecretKey2025"
	}

	fmt.Print("Callback Interval (seconds) [5]: ")
	interval, _ := reader.ReadString('\n')
	interval = strings.TrimSpace(interval)
	if interval == "" {
		interval = "5"
	}

	fmt.Print("Use TLS? (y/n) [n]: ")
	useTLS, _ := reader.ReadString('\n')
	useTLS = strings.TrimSpace(strings.ToLower(useTLS))

	protocol := "ws"
	if useTLS == "y" {
		protocol = "wss"
	}

	fmt.Print("\nOutput format [json/env/go]: ")
	format, _ := reader.ReadString('\n')
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "json"
	}

	switch format {
	case "json":
		serverURL := fmt.Sprintf("%s://%s:%s/api/agent", protocol, serverAddr, serverPort)
		config := map[string]interface{}{
			"server":   serverURL,
			"key":      key,
			"interval": interval,
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		filename := "agent_config.json"
		os.WriteFile(filename, data, 0644)
		fmt.Printf("\nConfiguration saved to %s\n", filename)
		fmt.Printf("Usage: agent.exe -config %s\n", filename)

	case "env":
		serverURL := fmt.Sprintf("%s://%s:%s/api/agent", protocol, serverAddr, serverPort)
		filename := "agent_config.env"
		envContent := fmt.Sprintf("RHINO_SERVER=%s\nRHINO_KEY=%s\nRHINO_INTERVAL=%s\n",
			serverURL, key, interval)
		os.WriteFile(filename, []byte(envContent), 0644)
		fmt.Printf("\nConfiguration saved to %s\n", filename)
		fmt.Println("Usage:")
		fmt.Println("  Windows: Get-Content agent_config.env | ForEach-Object { $var = $_.Split('='); [Environment]::SetEnvironmentVariable($var[0], $var[1], 'Process') }; .\\agent.exe")
		fmt.Println("  Linux: export $(cat agent_config.env | xargs) && ./agent")

	case "go":
		serverURL := fmt.Sprintf("%s://%s:%s/api/agent", protocol, serverAddr, serverPort)
		goConfig := fmt.Sprintf(`package main

const (
	ServerURL = "%s"
	EncryptionKey = "%s"
	CallbackInterval = %s
)
`, serverURL, key, interval)
		filename := "agent_config.go"
		os.WriteFile(filename, []byte(goConfig), 0644)
		fmt.Printf("\nConfiguration saved to %s\n", filename)
		fmt.Println("1. Copy to agent/ directory")
		fmt.Println("2. Update agent.go to use these constants")
		fmt.Println("3. Build: go build -ldflags=\"-s -w\" agent.go")
	}
}

func generateServerConfig(reader *bufio.Reader) {
	fmt.Println("\nServer Configuration")
	fmt.Println("--------------------")

	fmt.Print("Server Port [8443]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "8443"
	}

	fmt.Print("Bind Address [0.0.0.0]: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		host = "0.0.0.0"
	}

	fmt.Print("Encryption Key [RhinoC2SecretKey2024]: ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)
	if key == "" {
		key = "RhinoC2SecretKey2024"
	}

	fmt.Print("\nOutput format [json/env]: ")
	format, _ := reader.ReadString('\n')
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "json"
	}

	switch format {
	case "json":
		config := map[string]interface{}{
			"port": port,
			"host": host,
			"key":  key,
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		filename := "server_config.json"
		os.WriteFile(filename, data, 0644)
		fmt.Printf("\nConfiguration saved to %s\n", filename)
		fmt.Printf("Usage: server.exe -config %s\n", filename)

	case "env":
		filename := "server_config.env"
		envContent := fmt.Sprintf("RHINO_PORT=%s\nRHINO_HOST=%s\nRHINO_KEY=%s\n", port, host, key)
		os.WriteFile(filename, []byte(envContent), 0644)
		fmt.Printf("\nConfiguration saved to %s\n", filename)
		fmt.Println("Usage:")
		fmt.Println("  Windows: Get-Content server_config.env | ForEach-Object { $var = $_.Split('='); [Environment]::SetEnvironmentVariable($var[0], $var[1], 'Process') }; .\\server.exe")
		fmt.Println("  Linux: export $(cat server_config.env | xargs) && ./server")
	}

	fmt.Println("\nServer will be accessible at:")
	fmt.Printf("  Web Interface: http://localhost:%s\n", port)
	fmt.Printf("  REST API: http://localhost:%s/api/agents\n", port)
	fmt.Printf("  Agent WebSocket: ws://localhost:%s/api/agent\n", port)
}
