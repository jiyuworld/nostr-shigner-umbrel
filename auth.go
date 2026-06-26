package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "shigner_session"
	sessionTTL    = 7 * 24 * time.Hour
	minPwLen      = 8
)

type authConfig struct {
	PasswordHash string `json:"passwordHash"`
	CreatedAt    int64  `json:"createdAt"`
	UpdatedAt    int64  `json:"updatedAt,omitempty"`
}

func loadAuth() (authConfig, bool) {
	b, err := os.ReadFile(authFile)
	if err != nil {
		return authConfig{}, false
	}
	var a authConfig
	if json.Unmarshal(b, &a) != nil || a.PasswordHash == "" {
		return authConfig{}, false
	}
	return a, true
}

func saveAuth(a authConfig) error {
	b, _ := json.MarshalIndent(a, "", "  ")
	return os.WriteFile(authFile, b, 0o600)
}

func authConfigured() bool { _, ok := loadAuth(); return ok }

func setPassword(pw string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	cur, existed := loadAuth()
	created := now
	if existed && cur.CreatedAt > 0 {
		created = cur.CreatedAt
	}
	if err := saveAuth(authConfig{PasswordHash: string(hash), CreatedAt: created, UpdatedAt: now}); err != nil {
		return err
	}
	clearAllSessions()
	return nil
}

func checkPassword(pw string) bool {
	a, ok := loadAuth()
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(pw)) == nil
}

func seedPasswordFromEnv() {
	if authConfigured() {
		return
	}
	pw := os.Getenv("NOSTR_SHIGNER_WEB_PASSWORD")
	if len(pw) < minPwLen {
		if pw != "" {
			fmt.Printf("[web] ⚠ NOSTR_SHIGNER_WEB_PASSWORD ignored: must be at least %d characters\n", minPwLen)
		}
		return
	}
	if err := setPassword(pw); err != nil {
		fmt.Println("[web] ⚠ failed to seed password from env:", err)
		return
	}
	fmt.Println("[web] initial web password set from NOSTR_SHIGNER_WEB_PASSWORD")
}

type sessionEntry struct{ expires time.Time }

var (
	sessMu   sync.Mutex
	sessions = map[string]sessionEntry{}
)

func newSession() string {
	tok := newToken()
	sessMu.Lock()
	sessions[tok] = sessionEntry{expires: time.Now().Add(sessionTTL)}
	sessMu.Unlock()
	return tok
}

func validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(s.expires) {
		delete(sessions, c.Value)
		return false
	}
	sessions[c.Value] = sessionEntry{expires: time.Now().Add(sessionTTL)}
	return true
}

func clearSession(tok string) {
	sessMu.Lock()
	delete(sessions, tok)
	sessMu.Unlock()
}

func clearAllSessions() {
	sessMu.Lock()
	sessions = map[string]sessionEntry{}
	sessMu.Unlock()
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

type failRec struct {
	n         int
	windowEnd time.Time
	lockUntil time.Time
}

var (
	loginMu    sync.Mutex
	loginFails = map[string]*failRec{}
)

const (
	loginWindow     = 15 * time.Minute
	loginFreeTries  = 5
	loginLockStep   = 15 * time.Second
	loginMaxLockDur = 15 * time.Minute
)

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func loginAllowed(ip string) (bool, time.Duration) {
	loginMu.Lock()
	defer loginMu.Unlock()
	r := loginFails[ip]
	if r == nil {
		return true, 0
	}
	now := time.Now()
	if now.Before(r.lockUntil) {
		return false, r.lockUntil.Sub(now)
	}
	return true, 0
}

func loginFailed(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	now := time.Now()
	r := loginFails[ip]
	if r == nil || now.After(r.windowEnd) {
		r = &failRec{windowEnd: now.Add(loginWindow)}
		loginFails[ip] = r
	}
	r.n++
	if r.n > loginFreeTries {
		lock := time.Duration(r.n-loginFreeTries) * loginLockStep
		if lock > loginMaxLockDur {
			lock = loginMaxLockDur
		}
		r.lockUntil = now.Add(lock)
	}
}

func loginSucceeded(ip string) {
	loginMu.Lock()
	delete(loginFails, ip)
	loginMu.Unlock()
}

func authed(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authConfigured() {
			writeErr(w, http.StatusUnauthorized, "web ui is not set up yet")
			return
		}
		if !validSession(r) {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		fn(w, r)
	}
}

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"configured":    authConfigured(),
		"authenticated": validSession(r),
	})
}

func handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if authConfigured() {
		writeErr(w, http.StatusConflict, "web ui is already set up")
		return
	}
	var req pwReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(req.Password) < minPwLen {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("password must be at least %d characters.", minPwLen))
		return
	}
	if err := setPassword(req.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save password")
		return
	}
	tok := newSession()
	setSessionCookie(w, r, tok)
	writeOK(w, nil)
}

func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if ok, wait := loginAllowed(ip); !ok {
		writeErr(w, http.StatusTooManyRequests,
			fmt.Sprintf("too many attempts. try again in %ds.", int(wait.Seconds())+1))
		return
	}
	if !authConfigured() {
		writeErr(w, http.StatusConflict, "web ui is not set up yet")
		return
	}
	var req pwReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "password is required.")
		return
	}
	if !checkPassword(req.Password) {
		loginFailed(ip)
		writeErr(w, http.StatusUnauthorized, "incorrect password.")
		return
	}
	loginSucceeded(ip)
	tok := newSession()
	setSessionCookie(w, r, tok)
	writeOK(w, nil)
}

func handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		clearSession(c.Value)
	}
	clearSessionCookie(w, r)
	writeOK(w, nil)
}

type changePwReq struct {
	Current string `json:"current"`
	Next    string `json:"next"`
}

func handleAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePwReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !checkPassword(req.Current) {
		writeErr(w, http.StatusForbidden, "current password is incorrect.")
		return
	}
	if len(req.Next) < minPwLen {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("new password must be at least %d characters.", minPwLen))
		return
	}
	if err := setPassword(req.Next); err != nil { // also clears all sessions
		writeErr(w, http.StatusInternalServerError, "failed to save password")
		return
	}
	tok := newSession()
	setSessionCookie(w, r, tok)
	writeOK(w, nil)
}
