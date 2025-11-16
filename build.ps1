# RhinoC2 Build Script

param(
    [string]$Target = "all",
    [string]$OS = "windows",
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Build-Server {
    Write-Status "Building RhinoC2 Server..."
    Set-Location server
    go build -ldflags="-s -w" -o rhinoc2-server.exe server.go
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Server built: server/rhinoc2-server.exe"
    }
    else {
        Write-Error-Custom "Server build failed"
        exit 1
    }
    Set-Location ..
}

function Build-Agent {
    param(
        [string]$TargetOS,
        [string]$TargetArch
    )
    
    Write-Status "Building Agent for $TargetOS/$TargetArch..."
    
    $env:GOOS = $TargetOS
    $env:GOARCH = $TargetArch
    
    $ext = ""
    if ($TargetOS -eq "windows") {
        $ext = ".exe"
    }
    
    $outputName = "agent_${TargetOS}_${TargetArch}${ext}"
    
    Set-Location agent
    go build -ldflags="-s -w" -o $outputName agent.go
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Agent built: agent/$outputName"
        $size = (Get-Item $outputName).Length
        $sizeMB = [math]::Round($size / 1MB, 2)
        Write-Host "    Size: $sizeMB MB" -ForegroundColor Gray
    }
    else {
        Write-Error-Custom "Agent build failed for $TargetOS/$TargetArch"
    }
    
    Set-Location ..
    
    # Reset environment
    Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
}

function Build-All {
    Build-Server
    Write-Host ""
    
    # Windows builds
    Build-Agent "windows" "amd64"
    Build-Agent "windows" "386"
    
    # Linux builds
    Build-Agent "linux" "amd64"
    Build-Agent "linux" "386"
    Build-Agent "linux" "arm64"
    
    # macOS builds
    Build-Agent "darwin" "amd64"
    Build-Agent "darwin" "arm64"
}

function Show-Usage {
    Write-Host @"
RhinoC2 Build Script

Usage: .\build.ps1 [-Target <target>] [-OS <os>] [-Arch <arch>]

Targets:
    all        Build server and agents for all platforms (default)
    server     Build only the server
    agent      Build agent for specified OS/Arch

OS Options (for agent builds):
    windows, linux, darwin

Architecture Options:
    amd64, 386, arm64

Examples:
    .\build.ps1
    .\build.ps1 -Target server
    .\build.ps1 -Target agent -OS linux -Arch amd64
    .\build.ps1 -Target agent -OS windows -Arch 386

"@
}

# Main execution
Write-Host ""
Write-Host "=====================================" -ForegroundColor Yellow
Write-Host "   RhinoC2 Framework Build System   " -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Yellow
Write-Host ""

# Check if go is available
try {
    $goVersion = go version
    Write-Status "Go detected: $goVersion"
}
catch {
    Write-Error-Custom "Go is not installed or not in PATH"
    exit 1
}

# Download dependencies
Write-Status "Downloading dependencies..."
go mod download
Write-Host ""

switch ($Target.ToLower()) {
    "all" {
        Build-All
    }
    "server" {
        Build-Server
    }
    "agent" {
        Build-Agent $OS $Arch
    }
    "help" {
        Show-Usage
        exit 0
    }
    default {
        Write-Error-Custom "Unknown target: $Target"
        Show-Usage
        exit 1
    }
}

Write-Host ""
Write-Success "Build completed successfully!"
Write-Host ""
