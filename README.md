# RhinoC2

## v1.1.0

A modular command and control framework built in Go for penetration testing and authorized red team operations. Features encrypted agent communications, multi-session management, privilege detection, and a clean web interface for operator control.

> **⚠️ Detection Warning:** v1.1.0 is highly detectable by modern endpoint protection. No obfuscation, evasion, or OPSEC features are implemented. This version is for educational purposes and controlled lab environments only. Production evasion capabilities are planned for v1.3+.

## What is this?

RhinoC2 is a command and control framework designed for authorized penetration testing. It's split into clean modules that handle different aspects of post-exploitation work.

The project includes:
- Modular package structure for easy maintenance
- Encrypted communications using AES-256-GCM
- WebSocket-based agent connections
- Web control panel for managing agents
- Multi-agent session management
- Privilege and integrity level detection
- Cross-platform agent builds
- Over 20 command types

## Getting Started

Build everything with the included script:
```powershell
.\build.ps1
```

Start the server:
```powershell
cd server
.\rhinoc2-server.exe
```

The server will listen on `http://localhost:8443`. Run an agent and open that URL in your browser to access the control panel.

Deploy an agent:
```powershell
cd agent
.\agent_windows_amd64.exe
```

## Structure

```
RhinoC2/
├── agent/              Implant code
├── server/             C2 server 
├── client/             Web control panel
├── pkg/                Reusable modules
│   ├── crypto/         Encryption handling
│   ├── commands/       Command execution, file ops, networking
│   ├── persistence/    Various persistence methods
│   ├── evasion/        Anti-VM and sandbox checks
│   └── postexploit/    Cred harvesting, screenshots, etc.
├── cmd/                Helper utilities
└── build.ps1           Build script
```

## Features

Commands are organized into categories for easier use.

### Basic Commands

- `shell` - Execute shell commands
- `sysinfo` - Gather system info
- `ps` - List running processes
- `pwd` / `cd` / `ls` - File navigation
- `download` / `upload` - File transfer
- `scan_port` - Port scanning
- `net_interfaces` - Network enumeration

### Agent Management

- **Multi-agent sessions** - Manage multiple compromised hosts simultaneously
- **Privilege detection** - Automatically identifies if agent is running as admin/SYSTEM
- **Integrity levels** - Shows process integrity (High, Medium, Low)
- **Process tracking** - Displays PID and parent PID for each agent
- **Real-time status** - Live updates of agent connectivity and last seen times

### Persistence Options

Multiple methods to maintain access:

- Registry run keys
- Startup folder
- Scheduled tasks
- Windows services

### Other Capabilities

- VM and sandbox detection
- Credential harvesting
- Screenshot capture
- Clipboard monitoring

### Building for Windows

Build for all Windows platforms:
```powershell
.\build.ps1 -Target all
```

Or build specific targets:
```powershell
.\build.ps1 -Target agent -OS windows -Arch amd64
.\build.ps1 -Target agent -OS windows -Arch 386
```

## Testing

Run the test suite to verify everything works:
```powershell
.\test-all-features.ps1
```

## Configuration

Before using this in any real scenario, update the default settings:

**Change the encryption key** in both `server/server.go` and `agent/agent.go`:
```go
key := "YourCustomKey32BytesLongHere"
```

**Set your server address** in `agent/agent.go`:
```go
serverURL := "ws://your-server-ip:8443/api/agent"
```

**Adjust beacon interval** if needed:
```go
Interval: 30 * time.Second
```

## Important Notes

Change default encryption keys before deployment. Use TLS in production environments. This is for authorized testing only.

## Requirements

- Go 1.21 or newer
- gorilla/mux and gorilla/websocket packages
- golang.org/x/crypto for encryption

Dependencies are managed through go.mod and will be downloaded automatically during build.

## Extending

To add a new command:
1. Write the logic in the appropriate package under `pkg/`
2. Add a case in `agent/agent.go` handleTask function
3. Optionally add a button in the web panel

The modular structure makes it straightforward to add functionality without touching core components.

## Roadmap

### v1.2.0 (Planned)
- **Advanced persistence mechanisms** - WMI event subscriptions and service installation
- **Credential harvesting** - LSASS dumping and browser credential extraction
- **Network pivoting** - SOCKS proxy and port forwarding capabilities
- **Screenshot capture** - Remote desktop monitoring
- **Keylogging** - Input monitoring for target systems
- **Process injection** - Migrate into other processes for stealth
- **Anti-analysis** - VM and sandbox detection with automatic termination

## Legal

This is for authorized security testing and educational purposes. You're responsible for ensuring you have permission before using this on any systems. Unauthorized access to computer systems is illegal in most jurisdictions.

Use responsibly and legally.