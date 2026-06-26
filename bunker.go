package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const kindNostrConnect = 24133

type dmScheme int

const (
	schemeNIP44 dmScheme = iota
	schemeNIP04
)

func detectScheme(content string) dmScheme {
	if strings.Contains(content, "?iv=") {
		return schemeNIP04
	}
	return schemeNIP44
}

func decryptDM(sk []byte, peerPubHex, content string) (string, error) {
	if detectScheme(content) == schemeNIP04 {
		return nip04Decrypt(sk, peerPubHex, content)
	}
	return nip44Decrypt(sk, peerPubHex, content)
}

func encryptDM(sk []byte, peerPubHex, plaintext string, sc dmScheme) (string, error) {
	if sc == schemeNIP04 {
		return nip04Encrypt(sk, peerPubHex, plaintext)
	}
	return nip44Encrypt(sk, peerPubHex, plaintext)
}

func generateKey() string {
	for {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		d := new(big.Int).SetBytes(b)
		if d.Sign() != 0 && d.Cmp(curveN) < 0 {
			return encodeNsec(bytes32(d))
		}
	}
}

type nip46Request struct {
	ID     string   `json:"id"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

type nip46Response struct {
	ID     string `json:"id"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type clientInfo struct {
	name     string
	permsReq string // perms string the client requested at connect time (display only)
	perms    clientPerms
	source   string
	addedAt  int64
}

type clientPerms struct {
	GetPublicKey   bool  `json:"get_public_key"`
	SignEvent      bool  `json:"sign_event"`
	SignEventKinds []int `json:"sign_event_kinds,omitempty"` // empty = any kind allowed (when SignEvent is true)
	Nip04Encrypt   bool  `json:"nip04_encrypt"`
	Nip04Decrypt   bool  `json:"nip04_decrypt"`
	Nip44Encrypt   bool  `json:"nip44_encrypt"`
	Nip44Decrypt   bool  `json:"nip44_decrypt"`
	GetRelays      bool  `json:"get_relays"`
}

func defaultAllPerms() clientPerms {
	return clientPerms{
		GetPublicKey: true,
		SignEvent:    true,
		Nip04Encrypt: true,
		Nip04Decrypt: true,
		Nip44Encrypt: true,
		Nip44Decrypt: true,
		GetRelays:    true,
	}
}

func (p clientPerms) allows(method string, kind int) bool {
	switch method {
	case "connect", "ping", "disconnect":
		return true
	case "get_public_key":
		return p.GetPublicKey
	case "get_relays", "switch_relays":
		return p.GetRelays
	case "sign_event":
		if !p.SignEvent {
			return false
		}
		if len(p.SignEventKinds) == 0 {
			return true
		}
		for _, k := range p.SignEventKinds {
			if k == kind {
				return true
			}
		}
		return false
	case "nip04_encrypt":
		return p.Nip04Encrypt
	case "nip04_decrypt":
		return p.Nip04Decrypt
	case "nip44_encrypt":
		return p.Nip44Encrypt
	case "nip44_decrypt":
		return p.Nip44Decrypt
	default:
		return false
	}
}

func permsSummary(p *clientPerms) string {
	if p == nil {
		return "-"
	}
	var on []string
	if p.GetPublicKey {
		on = append(on, "get_public_key")
	}
	if p.SignEvent {
		if len(p.SignEventKinds) > 0 {
			ks := make([]string, len(p.SignEventKinds))
			for i, k := range p.SignEventKinds {
				ks[i] = strconv.Itoa(k)
			}
			on = append(on, "sign_event(kinds:"+strings.Join(ks, ",")+")")
		} else {
			on = append(on, "sign_event")
		}
	}
	if p.Nip04Encrypt {
		on = append(on, "nip04_encrypt")
	}
	if p.Nip04Decrypt {
		on = append(on, "nip04_decrypt")
	}
	if p.Nip44Encrypt {
		on = append(on, "nip44_encrypt")
	}
	if p.Nip44Decrypt {
		on = append(on, "nip44_decrypt")
	}
	if p.GetRelays {
		on = append(on, "get_relays")
	}
	if len(on) == 0 {
		return "(none)"
	}
	return strings.Join(on, ", ")
}

type persistedClient struct {
	Pubkey      string       `json:"pubkey"`
	Name        string       `json:"name,omitempty"`
	Perms       string       `json:"perms,omitempty"` // requested perms string (legacy / display)
	Permissions *clientPerms `json:"permissions,omitempty"`
	Source      string       `json:"source,omitempty"`
	AddedAt     int64        `json:"addedAt,omitempty"`
}

var (
	authMu      sync.RWMutex
	authClients = map[string]*clientInfo{}
)

func authorizeClient(pub, name, permsReq, source string) {
	authMu.Lock()
	if ex, ok := authClients[pub]; ok {
		if name != "" {
			ex.name = name
		}
		if permsReq != "" {
			ex.permsReq = permsReq
		}
		if ex.source == "" {
			ex.source = source
		}
	} else {
		authClients[pub] = &clientInfo{
			name:     name,
			permsReq: permsReq,
			perms:    defaultAllPerms(),
			source:   source,
			addedAt:  time.Now().Unix(),
		}
	}
	authMu.Unlock()
	persistClients()
}

func setClientPerms(pub string, p clientPerms) bool {
	authMu.Lock()
	ci, ok := authClients[pub]
	if ok {
		ci.perms = p
	}
	authMu.Unlock()
	if ok {
		persistClients()
	}
	return ok
}

func clientPermsOf(pub string) (clientPerms, bool) {
	authMu.RLock()
	defer authMu.RUnlock()
	if ci, ok := authClients[pub]; ok {
		return ci.perms, true
	}
	return clientPerms{}, false
}

func isAuthorized(pub string) bool {
	authMu.RLock()
	_, ok := authClients[pub]
	authMu.RUnlock()
	return ok
}

func revokeClient(pub string) bool {
	authMu.Lock()
	_, ok := authClients[pub]
	delete(authClients, pub)
	authMu.Unlock()
	if ok {
		persistClients()
	}
	return ok
}

func persistClients() {
	authMu.RLock()
	list := make([]persistedClient, 0, len(authClients))
	for pub, ci := range authClients {
		pcopy := ci.perms
		list = append(list, persistedClient{
			Pubkey:      pub,
			Name:        ci.name,
			Perms:       ci.permsReq,
			Permissions: &pcopy,
			Source:      ci.source,
			AddedAt:     ci.addedAt,
		})
	}
	authMu.RUnlock()
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(clientsFile, b, 0o600)
}

func loadClients() {
	b, err := os.ReadFile(clientsFile)
	if err != nil {
		return
	}
	var list []persistedClient
	if json.Unmarshal(b, &list) != nil {
		return
	}
	authMu.Lock()
	for _, c := range list {
		p := defaultAllPerms()
		if c.Permissions != nil {
			p = *c.Permissions
		}
		authClients[c.Pubkey] = &clientInfo{name: c.Name, permsReq: c.Perms, perms: p, source: c.Source, addedAt: c.AddedAt}
	}
	authMu.Unlock()
}

func loadOrCreateSecret() string {
	if b, err := os.ReadFile(secretFile); err == nil {
		s := strings.TrimSpace(string(b))
		if d, e := hex.DecodeString(s); e == nil && len(d) == 16 {
			return s
		}
	}
	tb := make([]byte, 16)
	_, _ = rand.Read(tb)
	s := hex.EncodeToString(tb)
	_ = os.WriteFile(secretFile, []byte(s), 0o600)
	return s
}

func permsSuffix(perms string) string {
	if perms == "" {
		return ""
	}
	return " [requested perms: " + perms + "]"
}

var (
	connsMu  sync.Mutex
	conns    = map[string]*wsConn{}
	servedMu sync.Mutex
	served   = map[string]bool{}
)

func setConn(relay string, ws *wsConn) { connsMu.Lock(); conns[relay] = ws; connsMu.Unlock() }
func getConn(relay string) *wsConn     { connsMu.Lock(); defer connsMu.Unlock(); return conns[relay] }
func delConn(relay string, ws *wsConn) {
	connsMu.Lock()
	if conns[relay] == ws {
		delete(conns, relay)
	}
	connsMu.Unlock()
}

func ensureRelay(relay string, sk []byte, pkHex, token string) {
	servedMu.Lock()
	if served[relay] {
		servedMu.Unlock()
		return
	}
	served[relay] = true
	servedMu.Unlock()
	go serveRelayLoop(relay, sk, pkHex, token)
}

func serveRelayLoop(relay string, sk []byte, pkHex, token string) {
	backoff := time.Second
	for {
		start := time.Now()
		err := serveRelay(relay, sk, pkHex, token)
		lasted := time.Since(start)
		if err != nil {
			fmt.Printf("[bunker] %s disconnected: %v\n", relay, err)
		}
		if lasted > 30*time.Second {
			backoff = time.Second
		}
		jitter := time.Duration(mrand.Int63n(int64(backoff/2 + 1)))
		wait := backoff + jitter
		fmt.Printf("[bunker] %s reconnecting after %s\n", relay, wait.Round(100*time.Millisecond))
		time.Sleep(wait)
		if backoff < 60*time.Second {
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}
}

var bunkerRelays []string

func runBunker(secArg string, relays []string) error {
	bunkerRelays = relays
	sk, err := parseSecret(secArg)
	if err != nil {
		return err
	}
	pkHex := hex.EncodeToString(pubkeyXOnly(sk))

	persist := loadSettings().PersistSecret
	var token string
	if persist {
		token = loadOrCreateSecret()
		loadClients()
	} else {
		tb := make([]byte, 16)
		_, _ = rand.Read(tb)
		token = hex.EncodeToString(tb)
	}
	persistClients()

	var rp strings.Builder
	for _, r := range relays {
		rp.WriteString("&relay=")
		rp.WriteString(r)
	}
	fmt.Printf("bunker://%s?secret=%s%s\n", pkHex, token, rp.String())
	fmt.Printf("[bunker] pubkey=%s\n", pkHex)
	fmt.Printf("[bunker] relays=%s\n", strings.Join(relays, " "))
	fmt.Printf("[bunker] persist secret=%v\n", persist)

	for _, relay := range relays {
		ensureRelay(relay, sk, pkHex, token)
	}
	go inboxPoller(sk, pkHex, token)
	go controlPoller()
	select {}
}

func controlPoller() {
	for {
		time.Sleep(time.Second)
		for _, line := range drainInbox(controlInbox) {
			applyControlLine(line)
		}
	}
}

func drainInbox(path string) []string {
	tmp := path + ".processing"
	if err := os.Rename(path, tmp); err != nil {
		return nil
	}
	b, err := os.ReadFile(tmp)
	os.Remove(tmp)
	if err != nil || len(b) == 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func applyControlLine(line string) {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) == 2 && parts[0] == "revoke" {
		if revokeClient(parts[1]) {
			fmt.Printf("[bunker] client revoked: %s\n", short(parts[1]))
		} else {
			fmt.Printf("[bunker] no client to revoke: %s\n", short(parts[1]))
		}
		return
	}
	if len(parts) == 3 && parts[0] == "setperms" {
		raw, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			fmt.Printf("[bunker] ⚠ setperms decode failed for %s: %v\n", short(parts[1]), err)
			return
		}
		var p clientPerms
		if err := json.Unmarshal(raw, &p); err != nil {
			fmt.Printf("[bunker] ⚠ setperms json failed for %s: %v\n", short(parts[1]), err)
			return
		}
		if setClientPerms(parts[1], p) {
			fmt.Printf("[bunker] perms updated for %s → %s\n", short(parts[1]), permsSummary(&p))
		} else {
			fmt.Printf("[bunker] no client for setperms: %s\n", short(parts[1]))
		}
		return
	}
}

type nostrConnectURI struct {
	clientPub string
	relays    []string
	secret    string
	perms     string
	name      string
}

func parseNostrConnect(uri string) (*nostrConnectURI, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "nostrconnect" {
		return nil, fmt.Errorf("not a nostrconnect:// uri")
	}
	pub := u.Host
	if b, err := hex.DecodeString(pub); err != nil || len(b) != 32 {
		return nil, fmt.Errorf("invalid client pubkey (64-char hex)")
	}
	q := u.Query()
	relays := q["relay"]
	if len(relays) == 0 {
		return nil, fmt.Errorf("no relay")
	}
	secret := q.Get("secret")
	if secret == "" {
		return nil, fmt.Errorf("no secret")
	}
	return &nostrConnectURI{clientPub: pub, relays: relays, secret: secret, perms: q.Get("perms"), name: q.Get("name")}, nil
}

func inboxPoller(sk []byte, pkHex, token string) {
	for {
		time.Sleep(time.Second)
		for _, line := range drainInbox(ncInbox) {
			processNostrConnect(line, sk, pkHex, token)
		}
	}
}

func processNostrConnect(uri string, sk []byte, pkHex, token string) {
	nc, err := parseNostrConnect(uri)
	if err != nil {
		fmt.Printf("[bunker] ⚠ nostrconnect parse failed: %v\n", err)
		return
	}

	authorizeClient(nc.clientPub, nc.name, nc.perms, "nostrconnect")
	fmt.Printf("[bunker] nostrconnect connect: %s (%s)%s\n", short(nc.clientPub), orDash(nc.name), permsSuffix(nc.perms))

	ackID := make([]byte, 8)
	_, _ = rand.Read(ackID)
	ack := &nip46Response{ID: hex.EncodeToString(ackID), Result: nc.secret}

	for _, relay := range nc.relays {
		ensureRelay(relay, sk, pkHex, token)
		go sendAck(relay, sk, nc.clientPub, ack)
	}
}

func sendAck(relay string, sk []byte, clientPub string, ack *nip46Response) {
	var ws *wsConn
	for i := 0; i < 50; i++ {
		if ws = getConn(relay); ws != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ws == nil {
		fmt.Printf("[bunker] ⚠ %s not connected — ack not sent\n", relay)
		return
	}
	out, err := buildResponseEvent(sk, clientPub, ack, schemeNIP44)
	if err != nil {
		fmt.Printf("[bunker] ⚠ ack build failed: %v\n", err)
		return
	}
	if err := ws.writeText(`["EVENT",` + out + `]`); err != nil {
		fmt.Printf("[bunker] ⚠ %s ack send failed: %v\n", relay, err)
		return
	}
	fmt.Printf("[bunker] %s nostrconnect ack sent → %s\n", relay, short(clientPub))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func serveRelay(relay string, sk []byte, pkHex, token string) error {
	ws, err := wsDial(relay)
	if err != nil {
		return err
	}
	defer ws.close()

	const pingInterval = 29 * time.Second
	ws.readDeadline = 95 * time.Second
	atomic.StoreInt32(&ws.alive, 1)
	stop := make(chan struct{})
	defer close(stop)
	go ws.keepaliveLoop(pingInterval, stop, relay)

	sub := fmt.Sprintf(`["REQ","nbm",{"kinds":[%d],"#p":["%s"],"since":%d}]`,
		kindNostrConnect, pkHex, time.Now().Unix()-10)
	if err := ws.writeText(sub); err != nil {
		return err
	}
	setConn(relay, ws)
	defer delConn(relay, ws)
	fmt.Printf("[bunker] %s subscription started\n", relay)

	for {
		msg, err := ws.readText()
		if err != nil {
			return err
		}
		var arr []json.RawMessage
		if json.Unmarshal([]byte(msg), &arr) != nil || len(arr) == 0 {
			continue
		}
		var typ string
		json.Unmarshal(arr[0], &typ)

		switch typ {
		case "OK":
			if len(arr) >= 4 {
				var ok bool
				var m string
				json.Unmarshal(arr[2], &ok)
				json.Unmarshal(arr[3], &m)
				if !ok {
					fmt.Printf("[bunker] ⚠ relay rejected response publish: %s\n", m)
				}
			}
			continue
		case "NOTICE":
			var m string
			if len(arr) >= 2 {
				json.Unmarshal(arr[1], &m)
			}
			fmt.Printf("[bunker] ⚠ NOTICE: %s\n", m)
			continue
		case "CLOSED":
			var m string
			if len(arr) >= 3 {
				json.Unmarshal(arr[2], &m)
			}
			fmt.Printf("[bunker] ⚠ subscription closed: %s — resubscribing\n", m)
			return fmt.Errorf("relay closed subscription: %s", m)
		case "EVENT":

		default:
			continue
		}

		if len(arr) < 3 {
			continue
		}
		var ev Event
		if json.Unmarshal(arr[2], &ev) != nil {
			continue
		}
		if ev.Kind != kindNostrConnect {
			continue
		}
		if !ev.verify() {
			fmt.Printf("[bunker] ⚠ ignoring request with invalid signature from %s\n", short(ev.Pubkey))
			continue
		}
		resp := handleRequest(sk, pkHex, token, &ev)
		if resp == nil {
			continue
		}
		out, berr := buildResponseEvent(sk, ev.Pubkey, resp, detectScheme(ev.Content))
		if berr != nil {
			fmt.Printf("[bunker] ⚠ response build failed: %v\n", berr)
			continue
		}
		if werr := ws.writeText(`["EVENT",` + out + `]`); werr != nil {
			fmt.Printf("[bunker] ⚠ response send failed: %v — reconnecting\n", werr)
			return werr
		}
		fmt.Printf("[bunker] response sent (%d bytes) → %s\n", len(out), relay)
	}
}

func handleRequest(sk []byte, pkHex, token string, ev *Event) *nip46Response {
	plain, err := decryptDM(sk, ev.Pubkey, ev.Content)
	if err != nil {
		fmt.Printf("[bunker] ⚠ request decrypt failed from %s: %v\n", short(ev.Pubkey), err)
		return nil
	}
	var req nip46Request
	if json.Unmarshal([]byte(plain), &req) != nil {
		fmt.Printf("[bunker] ⚠ request json parse failed from %s\n", short(ev.Pubkey))
		return nil
	}
	resp := &nip46Response{ID: req.ID}

	if req.Method == "connect" {

		secret := ""
		if len(req.Params) >= 2 {
			secret = req.Params[1]
		}

		if isAuthorized(ev.Pubkey) {
			resp.Result = "ack"
			fmt.Printf("[bunker] connect re-accepted (already authorized) from %s\n", short(ev.Pubkey))
			return resp
		}

		if subtle.ConstantTimeCompare([]byte(secret), []byte(token)) != 1 {
			resp.Error = "secret mismatch or missing"
			fmt.Printf("[bunker] ⚠ connect rejected (secret mismatch) from %s\n", short(ev.Pubkey))
			return resp
		}
		perms := ""
		if len(req.Params) >= 3 {
			perms = req.Params[2]
		}
		authorizeClient(ev.Pubkey, "", perms, "bunker")
		resp.Result = "ack"
		fmt.Printf("[bunker] connect accepted (authorized) from %s%s\n", short(ev.Pubkey), permsSuffix(perms))
		return resp
	}
	if req.Method == "ping" {
		resp.Result = "pong"
		return resp
	}

	if req.Method == "disconnect" {
		if isAuthorized(ev.Pubkey) {
			revokeClient(ev.Pubkey)
			fmt.Printf("[bunker] disconnect from %s — client revoked\n", short(ev.Pubkey))
		}
		resp.Result = "ack"
		return resp
	}

	if !isAuthorized(ev.Pubkey) {
		resp.Error = "unauthorized client"
		fmt.Printf("[bunker] ⚠ rejected unauthorized request method=%s from %s\n", req.Method, short(ev.Pubkey))
		return resp
	}

	perms, _ := clientPermsOf(ev.Pubkey)

	switch req.Method {
	case "get_public_key":
		if !perms.GetPublicKey {
			resp.Error = "permission denied: get_public_key not allowed for this client"
			break
		}
		resp.Result = pkHex
	case "get_relays":
		if !perms.GetRelays {
			resp.Error = "permission denied: get_relays not allowed for this client"
			break
		}
		// NIP-46 wants {relay: {read, write}}.
		rmap := make(map[string]map[string]bool, len(bunkerRelays))
		for _, r := range bunkerRelays {
			rmap[r] = map[string]bool{"read": true, "write": true}
		}
		if b, err := json.Marshal(rmap); err == nil {
			resp.Result = string(b)
		} else {
			resp.Result = "{}"
		}
	case "switch_relays":
		if !perms.GetRelays {
			resp.Error = "permission denied: switch_relays not allowed for this client"
			break
		}
		if b, err := json.Marshal(bunkerRelays); err == nil {
			resp.Result = string(b)
		} else {
			resp.Result = "null"
		}
	case "sign_event":
		if len(req.Params) < 1 {
			resp.Error = "no params"
			break
		}
		var unsigned Event
		if err := json.Unmarshal([]byte(req.Params[0]), &unsigned); err != nil {
			resp.Error = "event parse failed"
			break
		}
		if !perms.allows("sign_event", unsigned.Kind) {
			resp.Error = fmt.Sprintf("permission denied: sign_event (kind %d) not allowed for this client", unsigned.Kind)
			fmt.Printf("[bunker] ⚠ sign_event kind=%d denied by perms for %s\n", unsigned.Kind, short(ev.Pubkey))
			break
		}
		if unsigned.CreatedAt == 0 {
			unsigned.CreatedAt = time.Now().Unix()
		}
		if err := unsigned.sign(sk); err != nil {
			resp.Error = err.Error()
			break
		}
		signed, _ := json.Marshal(unsigned)
		resp.Result = string(signed)
		fmt.Printf("[bunker] sign_event kind=%d for %s\n", unsigned.Kind, short(ev.Pubkey))
	case "nip04_encrypt":
		if !perms.Nip04Encrypt {
			resp.Error = "permission denied: nip04_encrypt not allowed for this client"
			break
		}
		if len(req.Params) < 2 {
			resp.Error = "not enough params"
			break
		}
		ct, err := nip04Encrypt(sk, req.Params[0], req.Params[1])
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = ct
		}
	case "nip04_decrypt":
		if !perms.Nip04Decrypt {
			resp.Error = "permission denied: nip04_decrypt not allowed for this client"
			break
		}
		if len(req.Params) < 2 {
			resp.Error = "not enough params"
			break
		}
		pt, err := nip04Decrypt(sk, req.Params[0], req.Params[1])
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = pt
		}
	case "nip44_encrypt":
		if !perms.Nip44Encrypt {
			resp.Error = "permission denied: nip44_encrypt not allowed for this client"
			break
		}
		if len(req.Params) < 2 {
			resp.Error = "not enough params"
			break
		}
		ct, err := nip44Encrypt(sk, req.Params[0], req.Params[1])
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = ct
		}
	case "nip44_decrypt":
		if !perms.Nip44Decrypt {
			resp.Error = "permission denied: nip44_decrypt not allowed for this client"
			break
		}
		if len(req.Params) < 2 {
			resp.Error = "not enough params"
			break
		}
		pt, err := nip44Decrypt(sk, req.Params[0], req.Params[1])
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = pt
		}
	default:
		resp.Error = "unsupported method: " + req.Method
	}
	if resp.Error != "" {
		fmt.Printf("[bunker] ⚠ request failed method=%s: %s (from %s)\n", req.Method, resp.Error, short(ev.Pubkey))
	}
	return resp
}

func buildResponseEvent(sk []byte, clientPubHex string, resp *nip46Response, sc dmScheme) (string, error) {
	payload, _ := json.Marshal(resp)
	ct, err := encryptDM(sk, clientPubHex, string(payload), sc)
	if err != nil {
		return "", err
	}
	out := Event{
		CreatedAt: time.Now().Unix(),
		Kind:      kindNostrConnect,
		Tags:      [][]string{{"p", clientPubHex}},
		Content:   ct,
	}
	if err := out.sign(sk); err != nil {
		return "", err
	}
	b, err := json.Marshal(out)
	return string(b), err
}

func short(s string) string {
	if len(s) > 12 {
		return s[:8] + "…"
	}
	return s
}

func bunkerSubcommand() {
	relays := os.Args[2:]
	f := os.NewFile(3, "seckey")
	if f == nil {
		fmt.Println("[bunker] key input fd(3) missing")
		os.Exit(1)
	}
	line, _ := bufio.NewReader(f).ReadString('\n')
	f.Close()
	sec := strings.TrimSpace(line)
	if sec == "" || len(relays) == 0 {
		fmt.Println("[bunker] key or relays empty")
		os.Exit(1)
	}
	if err := runBunker(sec, relays); err != nil {
		fmt.Println("[bunker] error:", err)
		os.Exit(1)
	}
}
