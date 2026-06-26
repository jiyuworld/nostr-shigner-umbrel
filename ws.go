package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type wsConn struct {
	c            net.Conn
	r            *bufio.Reader
	wmu          sync.Mutex
	readDeadline time.Duration
	alive        int32
}

const wsWriteWait = 10 * time.Second

// "umbrel-host"/"host.docker.internal" resolve at dial time to the container's
// default gateway (the Docker host), so a co-located relay is reachable.
var (
	gwOnce sync.Once
	gwIP   string
)

func isHostAlias(h string) bool {
	return h == "umbrel-host" || h == "host.docker.internal"
}

func hostGatewayIP() string {
	gwOnce.Do(func() { gwIP = detectGatewayIP() })
	return gwIP
}

func detectGatewayIP() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		// default route; gateway in field[2] (little-endian hex).
		if fields[1] == "00000000" && fields[2] != "00000000" {
			return parseHexIPLE(fields[2])
		}
	}
	return ""
}

func parseHexIPLE(h string) string {
	if len(h) != 8 {
		return ""
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

func wsDial(rawURL string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	// If a dial rewrite is configured for this host[:port], dial that target
	// instead; the advertised rawURL is still used for routing and the URI.
	if m := loadSettings().RelayDial; len(m) > 0 {
		if t := m[strings.ToLower(u.Host)]; t != "" {
			if du, e := url.Parse(t); e == nil && du.Host != "" {
				fmt.Printf("[bunker] relay %s → dialing internal %s\n", rawURL, t)
				u = du
			} else {
				fmt.Printf("[bunker] ⚠ bad dial rewrite for %s: %q\n", rawURL, t)
			}
		}
	}

	var conn net.Conn

	port := u.Port()
	defPort := "80"
	if u.Scheme == "wss" {
		defPort = "443"
	}
	if port == "" {
		port = defPort
	}

	// For the host alias, try host.docker.internal first (compose extra_hosts),
	// then the default-route gateway; first to connect + handshake wins.
	var candidates []string
	if isHostAlias(u.Hostname()) {
		candidates = append(candidates, "host.docker.internal:"+port)
		if gw := hostGatewayIP(); gw != "" {
			candidates = append(candidates, gw+":"+port)
		}
	} else {
		host := u.Host
		if !strings.Contains(host, ":") {
			host += ":" + port
		}
		candidates = append(candidates, host)
	}

	var lastErr error
	for _, dialHost := range candidates {
		switch u.Scheme {
		case "wss":
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", dialHost,
				&tls.Config{ServerName: strings.Split(dialHost, ":")[0]})
		case "ws":
			conn, err = net.DialTimeout("tcp", dialHost, 15*time.Second)
		default:
			return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
		}
		if err != nil {
			fmt.Printf("[bunker] dial %s (→ %s) failed: %v\n", rawURL, dialHost, err)
			lastErr = err
			continue
		}
		fmt.Printf("[bunker] dial %s → %s connected\n", rawURL, dialHost)
		lastErr = nil
		break
	}
	if conn == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("no reachable address")
		}
		return nil, lastErr
	}

	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, u.Host, key)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	statusLine, err := r.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %s", strings.TrimSpace(statusLine))
	}

	want := acceptKey(key)
	ok := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		t := strings.TrimSpace(line)
		if t == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(t), "sec-websocket-accept:") {
			if strings.TrimSpace(t[len("sec-websocket-accept:"):]) == want {
				ok = true
			}
		}
	}
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("accept key mismatch")
	}
	return &wsConn{c: conn, r: r}, nil
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

func (w *wsConn) writeText(msg string) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	payload := []byte(msg)
	var hdr []byte
	b0 := byte(0x80 | 0x1)
	n := len(payload)
	switch {
	case n < 126:
		hdr = []byte{b0, byte(0x80 | n)}
	case n < 65536:
		hdr = []byte{b0, 0x80 | 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0], hdr[1] = b0, 0x80|127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	buf := append(append(hdr, mask...), masked...)
	w.c.SetWriteDeadline(time.Now().Add(wsWriteWait))
	_, err := w.c.Write(buf)
	return err
}

func (w *wsConn) readText() (string, error) {
	var data []byte
	for {
		if w.readDeadline > 0 {
			w.c.SetReadDeadline(time.Now().Add(w.readDeadline))
		}
		b0, err := w.r.ReadByte()
		if err != nil {
			return "", err
		}
		fin := b0&0x80 != 0
		opcode := b0 & 0x0f
		b1, err := w.r.ReadByte()
		if err != nil {
			return "", err
		}
		masked := b1&0x80 != 0
		ln := int(b1 & 0x7f)
		switch ln {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(w.r, ext[:]); err != nil {
				return "", err
			}
			ln = int(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(w.r, ext[:]); err != nil {
				return "", err
			}
			ln = int(binary.BigEndian.Uint64(ext[:]))
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(w.r, mask[:]); err != nil {
				return "", err
			}
		}
		payload := make([]byte, ln)
		if _, err := io.ReadFull(w.r, payload); err != nil {
			return "", err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		atomic.StoreInt32(&w.alive, 1)
		switch opcode {
		case 0x8:
			return "", io.EOF
		case 0x9:
			w.writePong(payload)
			continue
		case 0xA:
			continue
		case 0x1, 0x0:
			data = append(data, payload...)
			if fin {
				return string(data), nil
			}
		default:
			continue
		}
	}
}

func (w *wsConn) writePong(payload []byte) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	hdr := []byte{0x8A, byte(0x80 | len(payload))}
	w.c.SetWriteDeadline(time.Now().Add(wsWriteWait))
	w.c.Write(append(append(hdr, mask...), masked...))
}

func (w *wsConn) ping() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	hdr := []byte{0x89, 0x80}
	w.c.SetWriteDeadline(time.Now().Add(wsWriteWait))
	_, err := w.c.Write(append(hdr, mask...))
	return err
}

func (w *wsConn) keepaliveLoop(interval time.Duration, stop <-chan struct{}, label string) {
	t := time.NewTicker(interval)
	defer t.Stop()
	failures := 0
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if atomic.SwapInt32(&w.alive, 0) == 0 {
				failures++
				fmt.Printf("[bunker] %s ping unanswered (%d/3)\n", label, failures)
				if failures >= 3 {
					fmt.Printf("[bunker] %s 3 missed pings in a row → closing connection (reconnect)\n", label)
					w.close()
					return
				}
			} else {
				failures = 0
			}
			if err := w.ping(); err != nil {
				fmt.Printf("[bunker] %s ping send failed → closing connection: %v\n", label, err)
				w.close()
				return
			}
		}
	}
}

func (w *wsConn) close() { w.c.Close() }
