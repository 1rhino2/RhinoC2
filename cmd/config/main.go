package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("RhinoC2 Agent Configuration Generator")
	fmt.Println("======================================")

	fmt.Print("Server Address (e.g., 192.168.1.100): ")
	serverAddr, _ := reader.ReadString('\n')
	serverAddr = strings.TrimSpace(serverAddr)

	fmt.Print("Server Port [8443]: ")
	serverPort, _ := reader.ReadString('\n')
	serverPort = strings.TrimSpace(serverPort)
	if serverPort == "" {
		serverPort = "8443"
	}

	fmt.Print("Encryption Key: ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)
	if key == "" {
		key = "RhinoC2SecretKey2024"
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

	config := fmt.Sprintf(`// Auto-generated agent configuration
package main

const (
	ServerURL = "%s://%s:%s/api/agent"
	EncryptionKey = "%s"
	CallbackInterval = %s
)
`, protocol, serverAddr, serverPort, key, interval)

	filename := "agent_config.go"
	err := os.WriteFile(filename, []byte(config), 0644)
	if err != nil {
		fmt.Printf("Error writing config: %v\n", err)
		return
	}

	fmt.Printf("\nConfiguration saved to %s\n", filename)
	fmt.Println("\nNext steps:")
	fmt.Println("1. Copy this file to agent/ directory")
	fmt.Println("2. Update agent.go to use these constants")
	fmt.Println("3. Build the agent with: go build -ldflags=\"-s -w\" agent.go")
}
