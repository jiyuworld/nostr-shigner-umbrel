package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func dataDir() string {
	if d := os.Getenv("NOSTR_SHIGNER_DATA_DIR"); d != "" {
		return d
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".nostr-shigner")
	}
	return "/data/.nostr-shigner"
}

var (
	dir          = dataDir()
	keyFile      = filepath.Join(dir, "key.ncryptsec")
	relaysFile   = filepath.Join(dir, "relays")
	logFile      = filepath.Join(dir, "daemon.log")
	pidFile      = filepath.Join(dir, "daemon.pid")
	uriFile      = filepath.Join(dir, "bunker.uri")
	ncInbox      = filepath.Join(dir, "nostrconnect.inbox")
	settingsFile = filepath.Join(dir, "settings.json")
	secretFile   = filepath.Join(dir, "secret")
	clientsFile  = filepath.Join(dir, "clients.json")
	controlInbox = filepath.Join(dir, "control.inbox")
	authFile     = filepath.Join(dir, "auth.json")
)

const appVersion = "0.1.0-beta-0.0.1"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__bunker" {
		bunkerSubcommand()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "web" {
		runWebServer()
		return
	}
	fmt.Println("usage: nostr-shigner web")
	os.Exit(2)
}

func hasKey() bool { _, err := os.Stat(keyFile); return err == nil }

type appSettings struct {
	PersistSecret bool `json:"persistSecret"`
	// advertised relay host[:port] (lower-cased) -> internal ws[s]:// dial URL.
	RelayDial map[string]string `json:"relayDial,omitempty"`
}

func relayDialKey(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

func loadSettings() appSettings {
	var s appSettings
	if b, err := os.ReadFile(settingsFile); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveSettings(s appSettings) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(settingsFile, b, 0o600)
}

func loadClientsList() []persistedClient {
	b, err := os.ReadFile(clientsFile)
	if err != nil {
		return nil
	}
	var list []persistedClient
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].AddedAt < list[j].AddedAt })
	return list
}

func clientInList(pubkey string) bool {
	for _, c := range loadClientsList() {
		if c.Pubkey == pubkey {
			return true
		}
	}
	return false
}

func appendInbox(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func sendRevoke(pubkey string) error {
	return appendInbox(controlInbox, "revoke "+pubkey)
}

func waitClientGone(pubkey string, tries int) bool {
	for i := 0; i < tries; i++ {
		if !clientInList(pubkey) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func loadRelays() []string {
	b, err := os.ReadFile(relaysFile)
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

func saveRelays(r []string) {
	_ = os.WriteFile(relaysFile, []byte(strings.Join(r, " ")), 0o600)
}

func containsStr(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func runningPID() int {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	var pid int
	fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
	if pid <= 0 {
		return 0
	}
	if p, err := os.FindProcess(pid); err == nil {
		if p.Signal(syscall.Signal(0)) == nil {
			return pid
		}
	}
	return 0
}

func tailLines(lines []string, n int) []string {
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func waitForLog(marker string, fromSize int64, tries int) bool {
	for i := 0; i < tries; i++ {
		time.Sleep(500 * time.Millisecond)
		b, err := os.ReadFile(logFile)
		if err != nil || int64(len(b)) <= fromSize {
			continue
		}
		tail := string(b[fromSize:])
		if strings.Contains(tail, marker) {
			return true
		}
		for _, bad := range []string{"ack not sent", "ack build failed", "ack send failed", "nostrconnect parse failed"} {
			if strings.Contains(tail, bad) {
				return false
			}
		}
	}
	return false
}
