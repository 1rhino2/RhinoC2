# RhinoC2

Command and control framework for security testing

## Components

- gent/ - Implant
- server/ - C2 server
- client/ - Web panel
- pkg/crypto/ - Encryption (AES-256-GCM)
- pkg/commands/ - Shell, file ops, networking
- pkg/persistence/ - Registry, scheduled tasks

## Usage

Start server:
`
cd server
go run server.go
`

Run agent:
`
cd agent
go run agent.go
`

## Building

`
go build -o agent.exe ./agent
go build -o server.exe ./server
`
