# RhinoC2

A modular C2 framework written in Go for security testing and red team operations.

## What is this?

RhinoC2 is a command and control framework designed for authorized penetration testing. It's split into clean modules that handle different aspects of post-exploitation work.

The project includes:
- Modular package structure for easy maintenance
- Encrypted communications using AES-256-GCM
- WebSocket-based agent connections
- Web control panel for managing agents
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

### Building for Different Platforms

Build for all supported platforms:
```powershell
.\build.ps1 -Target all
```

Or build specific targets:
```powershell
.\build.ps1 -Target agent -OS linux -Arch amd64
.\build.ps1 -Target agent -OS darwin -Arch arm64
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

## Legal

This is for authorized security testing and educational purposes. You're responsible for ensuring you have permission before using this on any systems. Unauthorized access to computer systems is illegal in most jurisdictions.

Use responsibly and legally.