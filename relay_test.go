package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tgrelay/internal/mtproto/obfuscation"
	tlsrecord "tgrelay/internal/mtproto/record"
)

func testService(t *testing.T) *Service {
	t.Helper()
	store, err := openStore(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := newService(store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.close(); err != nil {
			t.Error(err)
		}
		store.db.Close()
	})
	return s
}
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
func seed(t *testing.T, s *Service, exits ...Outbound) {
	t.Helper()
	if err := s.update(func(c *Config) error {
		c.Inbounds = []Inbound{{ID: "in", Name: "测试入口", ListenIP: "127.0.0.1", Port: freePort(t), PublicHost: "127.0.0.1", TLSDomain: "storage.googleapis.com", Enabled: true}}
		c.Outbounds = exits
		c.Users = []User{{ID: "user", Name: "测试用户", Enabled: true}}
		c.Credentials = []Credential{{ID: "credential", InboundID: "in", UserID: "user", Secret: "367a189aee18fa31c190054efd4a8e95", Enabled: true}}
		if len(exits) > 0 {
			c.Routes = []Route{{ID: "route", Name: "测试路由", InboundIDs: []string{"in"}, OutboundID: exits[0].ID, Priority: 100, Enabled: true}}
		}
		return nil
	}, false); err != nil {
		t.Fatal(err)
	}
}

func mockSOCKS(t *testing.T, tag, password string) (Outbound, <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	requests := make(chan string, 16)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var header [4]byte
				if _, err := io.ReadFull(conn, header[:2]); err != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err = io.ReadFull(conn, methods); err != nil {
					return
				}
				method := byte(0)
				if password != "" {
					method = 2
				}
				if !bytes.Contains(methods, []byte{method}) {
					_ = writeAll(conn, []byte{5, 255})
					return
				}
				_ = writeAll(conn, []byte{5, method})
				if method == 2 {
					if _, err = io.ReadFull(conn, header[:2]); err != nil {
						return
					}
					name := make([]byte, int(header[1]))
					if _, err = io.ReadFull(conn, name); err != nil {
						return
					}
					if _, err = io.ReadFull(conn, header[:1]); err != nil {
						return
					}
					pass := make([]byte, int(header[0]))
					if _, err = io.ReadFull(conn, pass); err != nil {
						return
					}
					if string(pass) != password {
						_ = writeAll(conn, []byte{1, 1})
						return
					}
					_ = writeAll(conn, []byte{1, 0})
				}
				if _, err = io.ReadFull(conn, header[:]); err != nil {
					return
				}
				var host string
				switch header[3] {
				case 1:
					ip := make([]byte, 4)
					if _, err = io.ReadFull(conn, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 4:
					ip := make([]byte, 16)
					if _, err = io.ReadFull(conn, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 3:
					if _, err = io.ReadFull(conn, header[:1]); err != nil {
						return
					}
					name := make([]byte, int(header[0]))
					if _, err = io.ReadFull(conn, name); err != nil {
						return
					}
					host = string(name)
				default:
					return
				}
				if _, err = io.ReadFull(conn, header[:2]); err != nil {
					return
				}
				requests <- net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(header[:2])))
				_ = writeAll(conn, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				_, stream, err := (obfuscation.Obfuscator{}).ReadHandshake(conn)
				if err != nil {
					return
				}
				buf := make([]byte, 4096)
				for {
					n, err := stream.Read(buf)
					if n > 0 {
						if writeAll(stream, append([]byte(tag+":"), buf[:n]...)) != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return Outbound{ID: tag, Name: "测试落地 " + tag, Type: "SOCKS5", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Account: map[bool]string{true: "tester", false: ""}[password != ""], Password: password, Enabled: true}, requests
}

// Construct a client from an upstream captured ClientHello, with independent HMAC verification.
func connectTG(t *testing.T, s *Service) net.Conn {
	t.Helper()
	fixture, err := os.ReadFile("internal/mtproto/fake/testdata/client-hello-ok-19dfe38384b9884b.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Full string `json:"full"`
	}
	if err = json.Unmarshal(fixture, &f); err != nil {
		t.Fatal(err)
	}
	packet, _ := base64.StdEncoding.DecodeString(f.Full)
	clear(packet[11:43])
	_, _ = rand.Read(packet[44:76])
	key, _ := hex.DecodeString(s.config.Load().Credentials[0].Secret)
	digest := hmac.New(sha256.New, key)
	digest.Write(packet)
	random := digest.Sum(nil)
	binary.LittleEndian.PutUint32(random[28:], binary.LittleEndian.Uint32(random[28:])^uint32(time.Now().Unix()))
	copy(packet[11:43], random)
	n := s.config.Load().Inbounds[0]
	conn, err := net.DialTimeout("tcp", inboundAddress(&n), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = writeAll(conn, packet); err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	for range 3 {
		var header [5]byte
		if _, err = io.ReadFull(conn, header[:]); err != nil {
			t.Fatal(err)
		}
		response.Write(header[:])
		payload := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err = io.ReadFull(conn, payload); err != nil {
			t.Fatal(err)
		}
		response.Write(payload)
	}
	full := response.Bytes()
	serverRandom := bytes.Clone(full[11:43])
	clear(full[11:43])
	digest = hmac.New(sha256.New, key)
	digest.Write(random)
	digest.Write(full)
	if !hmac.Equal(serverRandom, digest.Sum(nil)) {
		t.Fatal("server Fake TLS authentication mismatch")
	}
	stream, err := (obfuscation.Obfuscator{Secret: key}).SendHandshake(tlsrecord.New(conn, true, true), 2)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}
func roundTrip(t *testing.T, conn net.Conn, payload, expected string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeAll(conn, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != expected {
		t.Fatalf("got %q, want %q", reply, expected)
	}
}

func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("connection remained readable")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("connection remained open until deadline")
	}
}

func TestAccessChangesCloseExistingConnections(t *testing.T) {
	changes := map[string]func(*Config){
		"expired":            func(c *Config) { c.Users[0].Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) },
		"quota exhausted":    func(c *Config) { c.Users[0].QuotaBytes = 1 },
		"credential revoked": func(c *Config) { c.Credentials = nil },
		"inbound stopped":    func(c *Config) { c.Inbounds[0].Enabled = false },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := testService(t)
			exit, _ := mockSOCKS(t, "A", "")
			seed(t, s, exit)
			conn := connectTG(t, s)
			roundTrip(t, conn, "check", "A:check")
			if err := s.update(func(c *Config) error { change(c); return nil }, false); err != nil {
				t.Fatal(err)
			}
			assertClosed(t, conn)
			if s.allowed("user", "credential", "in") {
				t.Fatal("access still allowed")
			}
		})
	}
}

func TestFakeTLSRoutingStableLinkAndUserStop(t *testing.T) {
	s := testService(t)
	a, requestsA := mockSOCKS(t, "A", "secret")
	b, requestsB := mockSOCKS(t, "B", "")
	seed(t, s, a, b)
	link := credentialLink(&s.config.Load().Inbounds[0], &s.config.Load().Credentials[0])
	first := connectTG(t, s)
	roundTrip(t, first, "one", "A:one")
	select {
	case target := <-requestsA:
		if target != "149.154.167.51:443" {
			t.Fatal(target)
		}
	case <-time.After(time.Second):
		t.Fatal("first route not used")
	}
	if err := s.update(func(c *Config) error { c.Routes[0].OutboundID = b.ID; return nil }, false); err != nil {
		t.Fatal(err)
	}
	if got := credentialLink(&s.config.Load().Inbounds[0], &s.config.Load().Credentials[0]); got != link {
		t.Fatal("route change altered TG link")
	}
	roundTrip(t, first, "old", "A:old")
	second := connectTG(t, s)
	roundTrip(t, second, "new", "B:new")
	select {
	case <-requestsB:
	case <-time.After(time.Second):
		t.Fatal("new route not used")
	}
	if err := s.update(func(c *Config) error { c.Users[0].Enabled = false; return nil }, false); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, first)
	used := s.usageSnapshot()["user:user"]
	if used.Upload != 9 || used.Download != 15 {
		t.Fatalf("unexpected actual stream accounting: %+v", used)
	}
}
func TestImmediateRouteSwitchClosesOldConnection(t *testing.T) {
	s := testService(t)
	a, _ := mockSOCKS(t, "A", "")
	b, _ := mockSOCKS(t, "B", "")
	seed(t, s, a, b)
	conn := connectTG(t, s)
	roundTrip(t, conn, "hello", "A:hello")
	if err := s.update(func(c *Config) error { c.Routes[0].OutboundID = b.ID; return nil }, true); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, conn)
}
func TestQuotaReservationsAreSharedAcrossConnections(t *testing.T) {
	s := testService(t)
	seed(t, s)
	if err := s.update(func(c *Config) error { c.Users[0].QuotaBytes = 1000; return nil }, false); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := s.reserve("user", 37)
			s.settle(&Session{UserID: "user", InboundID: "in", OutboundID: "out"}, n, n, true)
		}()
	}
	wg.Wait()
	if got := s.usageSnapshot()["user:user"].Total(); got != 1000 {
		t.Fatalf("quota overshot or undershot: %d", got)
	}
	if s.reserve("user", 1) != 0 {
		t.Fatal("exhausted quota still accepted bytes")
	}
}
func TestListenerFailureLeavesConfigAndDatabaseUnchanged(t *testing.T) {
	s := testService(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	revision := s.config.Load().Revision
	err = s.update(func(c *Config) error {
		c.Inbounds = append(c.Inbounds, Inbound{ID: "bad", Name: "busy", ListenIP: "127.0.0.1", Port: busy.Addr().(*net.TCPAddr).Port, PublicHost: "127.0.0.1", TLSDomain: "example.com", Enabled: true})
		return nil
	}, false)
	if err == nil {
		t.Fatal("expected bind failure")
	}
	stored, _, _, err := s.store.load()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != revision || s.config.Load().Revision != revision || len(stored.Inbounds) != 0 {
		t.Fatal("failed apply mutated state")
	}
}
func TestRoutePriorityAndFailClosed(t *testing.T) {
	c := &Config{Outbounds: []Outbound{{ID: "disabled", Enabled: false}, {ID: "ok", Enabled: true}}, Routes: []Route{{ID: "lower", Priority: 200, InboundIDs: []string{"in"}, OutboundID: "ok", Enabled: true}, {ID: "first", Priority: 10, InboundIDs: []string{"in"}, OutboundID: "disabled", Enabled: true}}}
	r, _, err := c.resolve("in")
	if err == nil || r.ID != "first" {
		t.Fatal("unusable matched exit fell through")
	}
	if _, _, err = c.resolve("missing"); err == nil {
		t.Fatal("unmatched inlet allowed")
	}
	if len(dcAddresses(999)) != 0 {
		t.Fatal("unknown DC allowed")
	}
}
func TestHTTPConnectPreservesBufferedTunnelBytes(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	request := make(chan *http.Request, 1)
	go func() {
		conn, _ := l.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		request <- req
		_ = writeAll(conn, []byte("HTTP/1.1 200 Connection Established\r\n\r\nTARGET"))
		var b [1]byte
		_, _ = conn.Read(b[:])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialOutbound(ctx, Outbound{Type: "HTTP", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Account: "account", Password: "pass", Enabled: true}, "149.154.167.51:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := make([]byte, 6)
	if _, err = io.ReadFull(conn, got); err != nil || string(got) != "TARGET" {
		t.Fatalf("lost buffered bytes: %q %v", got, err)
	}
	req := <-request
	if req.Method != "CONNECT" || req.Host != "149.154.167.51:443" || req.Header.Get("Proxy-Authorization") != "Basic YWNjb3VudDpwYXNz" {
		t.Fatal("incorrect CONNECT request")
	}
}
func TestHTTPSRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	var port int
	fmt.Sscan(portText, &port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialOutbound(ctx, Outbound{Type: "HTTPS", Host: host, Port: port, Enabled: true}, "149.154.167.51:443")
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("accepted untrusted exit certificate")
	}
}

func requestAPI(a *API, method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	return response
}
func TestAPIAuthenticationSecrecyAndPersistence(t *testing.T) {
	s := testService(t)
	a := newAPI(s, "", false)
	if got := requestAPI(a, "GET", "/api/state", "", nil).Code; got != 401 {
		t.Fatal(got)
	}
	setup := requestAPI(a, "POST", "/api/setup", `{"username":"admin","password":"test-password-12345"}`, nil)
	if setup.Code != 200 {
		t.Fatal(setup.Body.String())
	}
	cookies := setup.Result().Cookies()
	stale := httptest.NewRequest("POST", "http://localhost/api/users", strings.NewReader(`{"name":"stale"}`))
	stale.Header.Set("Content-Type", "application/json")
	stale.Header.Set("If-Match", "-1")
	for _, cookie := range cookies {
		stale.AddCookie(cookie)
	}
	conflict := httptest.NewRecorder()
	a.ServeHTTP(conflict, stale)
	if conflict.Code != 409 {
		t.Fatal("stale update was not rejected")
	}
	exit := Outbound{ID: "exit", Name: "测试出口", Type: "SOCKS5", Host: "127.0.0.1", Port: 1080, Password: "private-password", Enabled: true}
	seed(t, s, exit)
	response := requestAPI(a, "GET", "/api/state", "", cookies)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	if strings.Contains(response.Body.String(), exit.Password) || strings.Contains(response.Body.String(), s.config.Load().Credentials[0].Secret) {
		t.Fatal("state response leaked secrets")
	}
	var req = *httptest.NewRequest("POST", "http://localhost/api/users", strings.NewReader(`{"name":"blocked"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, &req)
	if rr.Code != 403 {
		t.Fatal("cross-site request allowed")
	}
	link := requestAPI(a, "GET", "/api/credentials/credential/link", "", cookies)
	if link.Code != 200 || !strings.Contains(link.Body.String(), "tg://proxy") {
		t.Fatal("missing authenticated link")
	}
	upload := s.reserve("user", 7)
	s.settle(&Session{UserID: "user", InboundID: "in", OutboundID: "exit"}, upload, upload, true)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	cfg, stored, _, err := s.store.load()
	if err != nil || stored["user:user"].Upload != 7 || len(cfg.Routes) != 1 {
		t.Fatalf("persistence failure: %v", err)
	}
	if got := requestAPI(a, "POST", "/api/logout", "", cookies).Code; got != 200 {
		t.Fatal(got)
	}
	if requestAPI(a, "GET", "/api/state", "", cookies).Code != 401 {
		t.Fatal("logout left active session")
	}
}
