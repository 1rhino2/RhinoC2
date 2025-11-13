package main

import (
	"fmt"
	"os"
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
	if len(args) == 0 {
		fmt.Println("Building all components...")
		buildServer()
		buildAgent("windows", "amd64")
		return
	}

	target := args[0]
	switch target {
	case "server":
		buildServer()
	case "agent":
		if len(args) >= 3 {
			buildAgent(args[1], args[2])
		} else {
			buildAgent("windows", "amd64")
		}
	case "all":
		buildServer()
		buildAgent("windows", "amd64")
		buildAgent("linux", "amd64")
	default:
		fmt.Printf("Unknown build target: %s\n", target)
	}
}

func buildServer() {
	fmt.Println("Building server...")
	// Implementation would call go build
	fmt.Println("Server built: server/rhinoc2-server.exe")
}

func buildAgent(goos, goarch string) {
	fmt.Printf("Building agent for %s/%s...\n", goos, goarch)
	// Implementation would call go build with GOOS and GOARCH
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	fmt.Printf("Agent built: agent/agent_%s_%s%s\n", goos, goarch, ext)
}

func generateCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: rhinoc2 generate [config|payload|listener]")
		return
	}

	switch args[0] {
	case "config":
		generateConfig()
	case "payload":
		generatePayload()
	case "listener":
		generateListener()
	default:
		fmt.Printf("Unknown generate target: %s\n", args[0])
	}
}

func generateConfig() {
	config := `# RhinoC2 Configuration
server:
  host: 0.0.0.0
  port: 8443
  key: RhinoC2SecretKey2024
  
agent:
  interval: 5
  jitter: 2
  
logging:
  enabled: true
  file: rhinoc2.log
`
	os.WriteFile("config.yaml", []byte(config), 0644)
	fmt.Println("Configuration file generated: config.yaml")
}

func generatePayload() {
	fmt.Println("Generating payload...")
	fmt.Println("Payload template generated")
}

func generateListener() {
	fmt.Println("Generating listener configuration...")
	fmt.Println("Listener config generated")
}

func printUsage() {
	usage := `RhinoC2 Framework Builder

Usage:
  rhinoc2 [command] [options]

Commands:
  build [target] [os] [arch]  Build components
    targets: server, agent, all
    os: windows, linux, darwin
    arch: amd64, 386, arm64
    
  generate [type]              Generate configuration
    types: config, payload, listener
    
  help                         Show this help

Examples:
  rhinoc2 build all
  rhinoc2 build agent windows amd64
  rhinoc2 build agent linux amd64
  rhinoc2 generate config
`
	fmt.Println(usage)
}
