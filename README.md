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
â”œâ”€â”€ agent/              Implant code
â”œâ”€â”€ server/             C2 server 
â”œâ”€â”€ client/             Web control panel
â”œâ”€â”€ pkg/                Reusable modules
â”‚   â”œâ”€â”€ crypto/         Encryption handling
â”‚   â”œâ”€â”€ commands/       Command execution, file ops, networking
â”‚   â”œâ”€â”€ persistence/    Various persistence methods
â”‚   â”œâ”€â”€ evasion/        Anti-VM and sandbox checks
â”‚   â””â”€â”€ postexploit/    Cred harvesting, screenshots, etc.
â”œâ”€â”€ cmd/                Helper utilities
â””â”€â”€ build.ps1           Build script
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
