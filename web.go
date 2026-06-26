package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web
var webAssets embed.FS

var webMu sync.Mutex

var csrfToken = newToken()

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func runWebServer() {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Printf("[web] ⚠ failed to create state dir (%s): %v\n", dir, err)
	}

	if err := checkDirWritable(dir); err != nil {
		fmt.Printf("[web] ⚠ cannot write to state dir (%s): %v\n", dir, err)
		fmt.Printf("[web]   container uid=%d gid=%d — the data volume must be owned by this uid.\n", os.Getuid(), os.Getgid())
		fmt.Println("[web]   → make sure docker-entrypoint.sh fixes /data ownership (see dockerfile).")
	}

	if runningPID() == 0 {
		_ = os.Remove(pidFile)
	}

	port := envOr("PORT", "3000")
	addr := envOr("NOSTR_SHIGNER_WEB_ADDR", "0.0.0.0") + ":" + port

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/app.js", staticHandler("web/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/theme.js", staticHandler("web/theme.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/style.css", staticHandler("web/style.css", "text/css; charset=utf-8"))

	// auth endpoints: reachable without a session.
	mux.HandleFunc("/api/auth/status", apiGet(handleAuthStatus))
	mux.HandleFunc("/api/auth/setup", apiPost(handleAuthSetup))
	mux.HandleFunc("/api/auth/login", apiPost(handleAuthLogin))
	mux.HandleFunc("/api/auth/logout", apiPost(authed(handleAuthLogout)))
	mux.HandleFunc("/api/auth/password", apiPost(authed(handleAuthChangePassword)))

	mux.HandleFunc("/api/status", apiGet(authed(handleStatus)))
	mux.HandleFunc("/api/bunker", apiGet(authed(handleBunker)))
	mux.HandleFunc("/api/relays", apiGet(authed(handleRelays)))
	mux.HandleFunc("/api/clients", apiGet(authed(handleClients)))
	mux.HandleFunc("/api/log", apiGet(authed(handleLog)))

	mux.HandleFunc("/api/key/generate", apiPost(authed(handleKeyGenerate)))
	mux.HandleFunc("/api/key/import", apiPost(authed(handleKeyImport)))
	mux.HandleFunc("/api/key/reveal", apiPost(authed(handleKeyReveal)))
	mux.HandleFunc("/api/key/delete", apiPost(authed(handleKeyDelete)))
	mux.HandleFunc("/api/relays/add", apiPost(authed(handleRelayAdd)))
	mux.HandleFunc("/api/relays/add-local", apiPost(authed(handleLocalRelayAdd)))
	mux.HandleFunc("/api/relays/remove", apiPost(authed(handleRelayRemove)))
	mux.HandleFunc("/api/settings", apiPost(authed(handleSettings)))
	mux.HandleFunc("/api/daemon/start", apiPost(authed(handleDaemonStart)))
	mux.HandleFunc("/api/daemon/stop", apiPost(authed(handleDaemonStop)))
	mux.HandleFunc("/api/nostrconnect", apiPost(authed(handleNostrConnect)))
	mux.HandleFunc("/api/clients/revoke", apiPost(authed(handleRevoke)))
	mux.HandleFunc("/api/clients/perms", apiPost(authed(handleClientPerms)))

	srv := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	seedPasswordFromEnv()

	go maybeAutoUnlock()

	if !authConfigured() {
		fmt.Println("[web] no web password set yet — open the UI to create one (first-run setup).")
	}
	fmt.Printf("[web] nostr-shigner gui listening on %s\n", addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("[web] server stopped:", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func checkDirWritable(d string) error {
	f, err := os.CreateTemp(d, ".wtest-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		// COOP is honored only on trustworthy (HTTPS/localhost) origins; sending
		// it over plain HTTP just yields a console warning, so skip it there.
		if isHTTPS(r) {
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
		}
		next.ServeHTTP(w, r)
	})
}

func apiGet(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "get only")
			return
		}
		noStore(w)
		fn(w, r)
	}
}

func apiPost(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "post only")
			return
		}

		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrfToken)) != 1 {
			writeErr(w, http.StatusForbidden, "csrf token mismatch")
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
			writeErr(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}

		if allow := os.Getenv("NOSTR_SHIGNER_ALLOWED_HOSTS"); allow != "" && !hostAllowed(r.Host, allow) {
			writeErr(w, http.StatusForbidden, "host not allowed")
			return
		}
		noStore(w)
		fn(w, r)
	}
}

func sameOrigin(origin, host string) bool {
	i := strings.Index(origin, "://")
	if i < 0 {
		return false
	}
	oh := origin[i+3:]
	return strings.EqualFold(oh, host)
}

func hostAllowed(host, allow string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	for _, a := range strings.Split(allow, ",") {
		if strings.EqualFold(strings.TrimSpace(a), h) {
			return true
		}
	}
	return false
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
func writeOK(w http.ResponseWriter, extra map[string]any) {
	m := map[string]any{"ok": true}
	for k, v := range extra {
		m[k] = v
	}
	writeJSON(w, m)
}

func readBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	return dec.Decode(dst)
}

func staticHandler(path, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := webAssets.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		if strings.HasSuffix(path, ".png") {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		_, _ = w.Write(b)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "index not found", http.StatusInternalServerError)
		return
	}
	out := strings.ReplaceAll(string(b), "{{CSRF}}", csrfToken)
	out = strings.ReplaceAll(out, "{{VERSION}}", appVersion)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	noStore(w)
	_, _ = w.Write([]byte(out))
}

func currentPubkeyHex() string {
	b, err := os.ReadFile(uriFile)
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`bunker://([0-9a-fA-F]{64})`).FindStringSubmatch(string(b))
	if len(m) == 2 {
		return strings.ToLower(m[1])
	}
	return ""
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	pid := runningPID()
	relays := loadRelays()
	st := loadSettings()
	resp := map[string]any{
		"hasKey":        hasKey(),
		"running":       pid != 0,
		"pid":           pid,
		"relays":        relays,
		"relayCount":    len(relays),
		"relayDial":     st.RelayDial,
		"hasUri":        fileSize(uriFile) > 0,
		"persistSecret": st.PersistSecret,
		"clientsCount":  len(loadClientsList()),
	}
	if pid != 0 {
		if pkHex := currentPubkeyHex(); pkHex != "" {
			if b, err := hex.DecodeString(pkHex); err == nil && len(b) == 32 {
				resp["npub"] = encodeNpub(b)
				resp["pubkey"] = pkHex
			}
		}
	}
	writeJSON(w, resp)
}

func handleBunker(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(uriFile)
	if err != nil || len(b) == 0 {
		writeErr(w, http.StatusNotFound, "no bunker:// yet. start the daemon once to generate it.")
		return
	}
	uri := strings.TrimSpace(string(b))
	svg, _ := qrSVG(uri)
	writeJSON(w, map[string]any{"uri": uri, "svg": svg})
}

func handleRelays(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"relays": loadRelays()})
}

func handleClients(w http.ResponseWriter, r *http.Request) {
	list := loadClientsList()
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		perms := defaultAllPerms()
		if c.Permissions != nil {
			perms = *c.Permissions
		}
		out = append(out, map[string]any{
			"pubkey": c.Pubkey, "name": c.Name, "permsRequested": c.Perms,
			"source": c.Source, "addedAt": c.AddedAt, "permissions": perms,
		})
	}
	writeJSON(w, map[string]any{"clients": out, "running": runningPID() != 0})
}

func handleLog(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("n"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 && x <= 1000 {
			n = x
		}
	}
	b, err := os.ReadFile(logFile)
	if err != nil {
		writeJSON(w, map[string]any{"lines": []string{}})
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	writeJSON(w, map[string]any{"lines": tailLines(lines, n)})
}

type keyGenReq struct {
	Password string `json:"password"`
	Replace  bool   `json:"replace"`
}

func handleKeyGenerate(w http.ResponseWriter, r *http.Request) {
	var req keyGenReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	webMu.Lock()
	defer webMu.Unlock()
	if hasKey() && !req.Replace {
		writeErr(w, http.StatusConflict, "a key already exists (use replace to overwrite).")
		return
	}
	if hasKey() && req.Replace && runningPID() != 0 {
		writeErr(w, http.StatusConflict, "cannot replace the key while the daemon is running. stop it first.")
		return
	}
	if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "password is required.")
		return
	}
	sk, err := parseSecret(generateKey())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	if err := saveEncryptedKeyWeb(sk, req.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, nil)
}

type keyImportReq struct {
	Secret   string `json:"secret"`
	Password string `json:"password"`
	Replace  bool   `json:"replace"`
}

func handleKeyImport(w http.ResponseWriter, r *http.Request) {
	var req keyImportReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	webMu.Lock()
	defer webMu.Unlock()
	if hasKey() && !req.Replace {
		writeErr(w, http.StatusConflict, "a key already exists (use replace to overwrite).")
		return
	}
	if hasKey() && req.Replace && runningPID() != 0 {
		writeErr(w, http.StatusConflict, "cannot replace the key while the daemon is running. stop it first.")
		return
	}
	in := strings.TrimSpace(req.Secret)
	if in == "" {
		writeErr(w, http.StatusBadRequest, "key input is empty.")
		return
	}
	if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "password is required.")
		return
	}
	if strings.HasPrefix(in, "ncryptsec1") {

		sk, err := nip49Decrypt(in, req.Password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "ncryptsec verification failed (check password)")
			return
		}
		zero(sk)
		if err := os.WriteFile(keyFile, []byte(in), 0o600); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("save failed (%s): %v", keyFile, err))
			return
		}
		writeOK(w, nil)
		return
	}
	sk, err := parseSecret(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid key format: "+err.Error())
		return
	}
	if err := saveEncryptedKeyWeb(sk, req.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, nil)
}

func saveEncryptedKeyWeb(sk []byte, pw string) error {
	ncs, err := nip49Encrypt(sk, pw, 16)
	zero(sk)
	if err != nil {
		return fmt.Errorf("encryption failed")
	}
	if err := os.WriteFile(keyFile, []byte(ncs), 0o600); err != nil {
		return fmt.Errorf("save failed (%s): %v", keyFile, err)
	}
	return nil
}

type pwReq struct {
	Password string `json:"password"`
}

func handleKeyReveal(w http.ResponseWriter, r *http.Request) {
	var req pwReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	b, err := os.ReadFile(keyFile)
	if err != nil || len(b) == 0 {
		writeErr(w, http.StatusNotFound, "no key saved.")
		return
	}
	ncs := strings.TrimSpace(string(b))
	sk, err := nip49Decrypt(ncs, req.Password)
	if err != nil {
		writeErr(w, http.StatusForbidden, "password is incorrect.")
		return
	}
	zero(sk)
	writeOK(w, map[string]any{"ncryptsec": ncs})
}

type confirmReq struct {
	Confirm bool `json:"confirm"`
}

func handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	var req confirmReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !req.Confirm {
		writeErr(w, http.StatusBadRequest, "confirmation required.")
		return
	}
	webMu.Lock()
	defer webMu.Unlock()
	if runningPID() != 0 {
		writeErr(w, http.StatusConflict, "cannot delete the key while the daemon is running. stop it first.")
		return
	}
	_ = os.Remove(keyFile)
	_ = os.Remove(uriFile)
	writeOK(w, nil)
}

type relayAddReq struct {
	Relays string `json:"relays"`
}

func handleRelayAdd(w http.ResponseWriter, r *http.Request) {
	var req relayAddReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	webMu.Lock()
	defer webMu.Unlock()
	relays := loadRelays()
	added := 0
	var skipped []string
	for _, f := range strings.FieldsFunc(req.Relays, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.HasPrefix(f, "wss://") && !strings.HasPrefix(f, "ws://") {
			skipped = append(skipped, f)
			continue
		}
		if containsStr(relays, f) {
			continue
		}
		relays = append(relays, f)
		added++
	}
	saveRelays(relays)
	writeOK(w, map[string]any{"added": added, "skipped": skipped, "relays": relays})
}

type relayRemoveReq struct {
	Relay string `json:"relay"`
}

func handleRelayRemove(w http.ResponseWriter, r *http.Request) {
	var req relayRemoveReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	webMu.Lock()
	defer webMu.Unlock()
	relays := loadRelays()
	out := relays[:0]
	for _, x := range relays {
		if x != req.Relay {
			out = append(out, x)
		}
	}
	saveRelays(out)
	if key := relayDialKey(req.Relay); key != "" {
		s := loadSettings()
		if _, ok := s.RelayDial[key]; ok {
			delete(s.RelayDial, key)
			_ = saveSettings(s)
		}
	}
	writeOK(w, map[string]any{"relays": out})
}

type settingsReq struct {
	PersistSecret bool `json:"persistSecret"`
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	webMu.Lock()
	defer webMu.Unlock()
	s := loadSettings() // preserve other fields (e.g. RelayDial)
	s.PersistSecret = req.PersistSecret
	if err := saveSettings(s); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save settings")
		return
	}
	writeOK(w, map[string]any{"persistSecret": req.PersistSecret})
}

type localRelayReq struct {
	Advertise string `json:"advertise"` // client-reachable, goes in bunker URI (e.g. ws://umbrel:4848)
	Internal  string `json:"internal"`  // daemon dial target (e.g. nostr-relay_relay_1:8080 or ws://...)
}

func handleLocalRelayAdd(w http.ResponseWriter, r *http.Request) {
	var req localRelayReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	adv := normalizeRelayURL(req.Advertise)
	internal := normalizeRelayURL(req.Internal)
	if adv == "" {
		writeErr(w, http.StatusBadRequest, "advertise URL must be ws:// or wss://")
		return
	}
	if internal == "" {
		writeErr(w, http.StatusBadRequest, "internal address must resolve to ws:// or wss://")
		return
	}
	key := relayDialKey(adv)
	if key == "" {
		writeErr(w, http.StatusBadRequest, "invalid advertise host")
		return
	}
	webMu.Lock()
	defer webMu.Unlock()

	relays := loadRelays()
	if !containsStr(relays, adv) {
		relays = append(relays, adv)
		saveRelays(relays)
	}
	s := loadSettings()
	if s.RelayDial == nil {
		s.RelayDial = map[string]string{}
	}
	s.RelayDial[key] = internal
	if err := saveSettings(s); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save settings")
		return
	}
	writeOK(w, map[string]any{"relays": relays, "advertise": adv, "internal": internal})
}

func normalizeRelayURL(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	if !strings.HasPrefix(in, "ws://") && !strings.HasPrefix(in, "wss://") {
		in = "ws://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := u.Host
	if u.Port() == "" && u.Scheme == "ws" {
		host += ":8080"
	}
	return u.Scheme + "://" + host
}

func handleDaemonStart(w http.ResponseWriter, r *http.Request) {
	var req pwReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	uri, pid, err := startDaemonWeb(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"pid": pid, "uri": uri})
}

func handleDaemonStop(w http.ResponseWriter, r *http.Request) {
	webMu.Lock()
	defer webMu.Unlock()
	pid := runningPID()
	if pid == 0 {
		_ = os.Remove(pidFile)
		writeOK(w, map[string]any{"running": false})
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Signal(syscall.SIGTERM)
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
	}
	_ = os.Remove(pidFile)
	writeOK(w, map[string]any{"running": false})
}

func startDaemonWeb(password string) (string, int, error) {
	webMu.Lock()
	defer webMu.Unlock()

	if !hasKey() {
		return "", 0, fmt.Errorf("add a private key first.")
	}
	if len(loadRelays()) == 0 {
		return "", 0, fmt.Errorf("no relays. add a relay first.")
	}
	if pid := runningPID(); pid != 0 {
		return strings.TrimSpace(readFileStr(uriFile)), pid, nil
	}
	if password == "" {
		return "", 0, fmt.Errorf("password is required.")
	}

	data, _ := os.ReadFile(keyFile)
	sk, err := nip49Decrypt(strings.TrimSpace(string(data)), password)
	if err != nil {
		return "", 0, fmt.Errorf("decryption failed (check password)")
	}
	keyHex := hex.EncodeToString(sk)
	zero(sk)
	relays := loadRelays()

	lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		keyHex = ""
		return "", 0, fmt.Errorf("failed to open log file")
	}
	defer lf.Close()

	self, err := os.Executable()
	if err != nil {
		keyHex = ""
		return "", 0, fmt.Errorf("failed to resolve executable path")
	}
	pr, pw2, err := os.Pipe()
	if err != nil {
		keyHex = ""
		return "", 0, fmt.Errorf("failed to create pipe")
	}
	args := append([]string{"__bunker"}, relays...)
	cmd := exec.Command(self, args...)
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.Stdin = nil
	cmd.ExtraFiles = []*os.File{pr}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw2.Close()
		keyHex = ""
		return "", 0, fmt.Errorf("failed to start daemon")
	}
	pr.Close()
	io.WriteString(pw2, keyHex+"\n")
	pw2.Close()
	keyHex = ""
	go cmd.Wait()
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)

	re := regexp.MustCompile(`bunker://\S+`)
	var uri string
	for i := 0; i < 16; i++ {
		time.Sleep(500 * time.Millisecond)
		if b, _ := os.ReadFile(logFile); len(b) > 0 {
			if m := re.FindString(string(b)); m != "" {
				uri = m
				break
			}
		}
		if runningPID() == 0 {
			break
		}
	}
	if runningPID() == 0 {
		_ = os.Remove(pidFile)
		return "", 0, fmt.Errorf("daemon exited immediately. check the log.")
	}
	if uri != "" {
		_ = os.WriteFile(uriFile, []byte(uri), 0o600)
	}
	return uri, runningPID(), nil
}

func readFileStr(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

type ncReq struct {
	URI string `json:"uri"`
}

func handleNostrConnect(w http.ResponseWriter, r *http.Request) {
	var req ncReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	in := strings.TrimSpace(req.URI)
	nc, err := parseNostrConnect(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "uri error: "+err.Error())
		return
	}
	if runningPID() == 0 {
		writeErr(w, http.StatusConflict, "daemon is not running. start it first.")
		return
	}
	webMu.Lock()
	relays := loadRelays()
	for _, r := range nc.relays {
		if !containsStr(relays, r) {
			relays = append(relays, r)
		}
	}
	saveRelays(relays)
	logSize := fileSize(logFile)
	err = appendInbox(ncInbox, in)
	webMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to forward to daemon")
		return
	}
	ok := waitForLog("nostrconnect ack sent → "+short(nc.clientPub), logSize, 16)
	writeOK(w, map[string]any{"ack": ok, "client": nc.clientPub, "name": nc.name})
}

type revokeReq struct {
	Pubkey string `json:"pubkey"`
}

func handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req revokeReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Pubkey == "" {
		writeErr(w, http.StatusBadRequest, "pubkey is required.")
		return
	}
	if runningPID() == 0 {
		writeErr(w, http.StatusConflict, "revoking is only possible while the daemon runs.")
		return
	}
	if err := sendRevoke(req.Pubkey); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to send command")
		return
	}
	ok := waitClientGone(req.Pubkey, 30)
	writeOK(w, map[string]any{"removed": ok})
}

type clientPermsReq struct {
	Pubkey string      `json:"pubkey"`
	Perms  clientPerms `json:"perms"`
}

func handleClientPerms(w http.ResponseWriter, r *http.Request) {
	var req clientPermsReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Pubkey == "" {
		writeErr(w, http.StatusBadRequest, "pubkey is required.")
		return
	}
	req.Perms = sanitizePerms(req.Perms)
	if !clientInList(req.Pubkey) {
		writeErr(w, http.StatusNotFound, "unknown client.")
		return
	}

	if runningPID() != 0 {
		b, _ := json.Marshal(req.Perms)
		line := "setperms " + req.Pubkey + " " + base64.StdEncoding.EncodeToString(b)
		if err := appendInbox(controlInbox, line); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to send command")
			return
		}
		applied := waitPermsApplied(req.Pubkey, req.Perms, 30)
		writeOK(w, map[string]any{"applied": applied, "permissions": req.Perms})
		return
	}

	if err := updatePersistedPerms(req.Pubkey, req.Perms); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"applied": true, "permissions": req.Perms})
}

func sanitizePerms(p clientPerms) clientPerms {
	if !p.SignEvent {
		p.SignEventKinds = nil
		return p
	}
	if len(p.SignEventKinds) == 0 {
		return p
	}
	seen := map[int]bool{}
	var ks []int
	for _, k := range p.SignEventKinds {
		if k < 0 || seen[k] {
			continue
		}
		seen[k] = true
		ks = append(ks, k)
	}
	p.SignEventKinds = ks
	return p
}

func permsEqual(a, b clientPerms) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func waitPermsApplied(pub string, want clientPerms, tries int) bool {
	for i := 0; i < tries; i++ {
		for _, c := range loadClientsList() {
			if c.Pubkey == pub && c.Permissions != nil && permsEqual(*c.Permissions, want) {
				return true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func updatePersistedPerms(pub string, p clientPerms) error {
	webMu.Lock()
	defer webMu.Unlock()
	list := loadClientsList()
	found := false
	for i := range list {
		if list[i].Pubkey == pub {
			pc := p
			list[i].Permissions = &pc
			found = true
		}
	}
	if !found {
		return fmt.Errorf("unknown client")
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode clients")
	}
	if err := os.WriteFile(clientsFile, b, 0o600); err != nil {
		return fmt.Errorf("failed to save clients")
	}
	return nil
}

func maybeAutoUnlock() {
	pwFile := os.Getenv("NOSTR_SHIGNER_AUTO_UNLOCK_FILE")
	if pwFile == "" {
		return
	}
	b, err := os.ReadFile(pwFile)
	if err != nil {
		fmt.Println("[web] auto-unlock: failed to read password file:", err)
		return
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if pw == "" || !hasKey() || len(loadRelays()) == 0 {
		return
	}
	time.Sleep(time.Second)
	if _, _, err := startDaemonWeb(pw); err != nil {
		fmt.Println("[web] auto-unlock failed:", err)
	} else {
		fmt.Println("[web] daemon started via auto-unlock")
	}
	pw = ""
}

func qrSVG(text string) (string, error) {
	m, err := qrMatrix(text)
	if err != nil {
		return "", err
	}
	const quiet = 4
	dim := m.size + quiet*2
	var path strings.Builder
	for r := 0; r < m.size; r++ {
		for c := 0; c < m.size; c++ {
			if m.mod[r][c] {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", c+quiet, r+quiet)
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="bunker QR">`,
		dim, dim)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#ffffff"/>`, dim, dim)
	fmt.Fprintf(&b, `<path d="%s" fill="#0e1014"/>`, path.String())
	b.WriteString(`</svg>`)
	return b.String(), nil
}
