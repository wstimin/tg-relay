package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStartupIsolatesPortConflictsAndRecovers(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	store, err := openStore(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	goodPort := freePort(t)
	c := &Config{Settings: Settings{Workspace: "test"}, Inbounds: []Inbound{
		{ID: "good", Name: "good", ListenIP: "127.0.0.1", Port: goodPort, PublicHost: "relay.example.com", TLSDomain: "www.apple.com", Enabled: true},
		{ID: "busy", Name: "busy", ListenIP: "127.0.0.1", Port: busy.Addr().(*net.TCPAddr).Port, PublicHost: "relay.example.com", TLSDomain: "www.apple.com", Enabled: true},
	}}
	if err := store.saveConfig(c); err != nil {
		t.Fatal(err)
	}
	s, err := newService(store)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", goodPort), time.Second)
	if err != nil {
		t.Fatal("unrelated inbound failed", err)
	}
	conn.Close()
	if s.engine.ready() {
		t.Fatal("conflicting listener was reported ready")
	}
	if !strings.Contains(s.engine.snapshot()["busy"].(map[string]any)["error"].(string), "占用") {
		t.Fatal("missing actual listener error")
	}
	busy.Close()
	s.reconcileListeners()
	if !s.engine.ready() {
		t.Fatal("listener did not recover")
	}
}

func TestSourceHandshakeLimitDoesNotBlockOtherClients(t *testing.T) {
	s := testService(t)
	exit, _ := mockSOCKS(t, "ok", "")
	seed(t, s, exit)
	address := inboundAddress(&s.config.Load().Inbounds[0])
	var stalled []net.Conn
	defer func() {
		for _, c := range stalled {
			c.Close()
		}
	}()
	for range 16 {
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		stalled = append(stalled, c)
	}
	until := time.Now().Add(time.Second)
	for {
		s.engine.mu.Lock()
		count := s.engine.pendingTotal
		s.engine.mu.Unlock()
		if count == 16 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("pending handshakes did not start")
		}
		time.Sleep(time.Millisecond)
	}
	extra, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := extra.Read(b[:]); err == nil {
		t.Fatal("source limit not enforced")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("extra source connection was not rejected")
	}
	client := connectTG(t, s, "127.0.0.2")
	roundTrip(t, client, "ping", "ok:ping")
	client.Close()
	if s.engine.snapshot()["in"].(map[string]any)["failures"].(map[string]uint64)["握手限流"] == 0 {
		t.Fatal("limit failure counter missing")
	}
}

func TestHandshakeQueueWaitsForCapacity(t *testing.T) {
	s := testService(t)
	exit, _ := mockSOCKS(t, "ok", "")
	seed(t, s, exit)
	for range cap(s.engine.handshakes) {
		s.engine.handshakes <- struct{}{}
	}
	go func() { time.Sleep(100 * time.Millisecond); <-s.engine.handshakes }()
	client := connectTG(t, s)
	roundTrip(t, client, "ping", "ok:ping")
}

func TestDCConnectionRacesStalledCandidateAndClosesLosers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan string, 16)
	closed := make(chan struct{}, 16)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				requests <- req.Host
				if req.Host == dcAddresses(2)[0] {
					io.Copy(io.Discard, c)
					closed <- struct{}{}
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				io.Copy(c, c)
			}()
		}
	}()
	s := testService(t)
	exit := Outbound{ID: "http", Name: "http", Type: "HTTP", Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Enabled: true}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	conn, err := s.engine.dialDC(ctx, exit, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if time.Since(started) > time.Second {
		t.Fatal("stalled candidate delayed usable alternative")
	}
	roundTrip(t, conn, "ping", "ping")
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("losing tunnel not cancelled")
	}
	first, second := <-requests, <-requests
	if first != dcAddresses(2)[0] || second == first {
		t.Fatal("wrong candidate routing", first, second)
	}
	next, err := s.engine.dialDC(ctx, exit, 2)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	if got := <-requests; got != second {
		t.Fatal("successful tunnel was not preferred", got)
	}
}

func TestTrustedProxySeparatesClientsAndRejectsSpoofedHeaders(t *testing.T) {
	s := testService(t)
	if _, err := s.store.saveAdmin("admin", "123456", false); err != nil {
		t.Fatal(err)
	}
	a := newAPI(s, "panel.example.com", true)
	a.trustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	request := func(body, peer, forwarded string) int {
		r := httptest.NewRequest("POST", "https://panel.example.com/api/login", strings.NewReader(body))
		r.RemoteAddr = peer
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", forwarded)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Code
	}
	for range 10 {
		if status := request(`{"username":"admin","password":"wrong1"}`, "127.0.0.1:1234", "198.51.100.1"); status != 401 {
			t.Fatal(status)
		}
	}
	if status := request(`{"username":"admin","password":"123456"}`, "127.0.0.1:1234", "203.0.113.2"); status != 200 {
		t.Fatal("another visitor was locked out", status)
	}
	if status := request(`{"username":"admin","password":"123456"}`, "127.0.0.1:1234", ""); status != 400 {
		t.Fatal("missing proxy source accepted", status)
	}
	for range 12 {
		if status := request("{", "127.0.0.1:1234", "203.0.113.2"); status != 400 {
			t.Fatal(status)
		}
	}
	if status := request(`{"username":"admin","password":"123456"}`, "127.0.0.1:1234", "203.0.113.2"); status != 200 {
		t.Fatal("invalid JSON poisoned login limits", status)
	}
	for _, tc := range []struct{ peer, forwarded, want string }{
		{"198.51.100.1:2345", "203.0.113.2", "198.51.100.1"},
		{"127.0.0.1:2345", "203.0.113.99, 198.51.100.1", "198.51.100.1"},
	} {
		r := httptest.NewRequest("POST", "https://panel.example.com/api/login", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.forwarded)
		if got, err := a.loginPeer(r); err != nil || got != tc.want {
			t.Fatal("forwarded address trust failed", got, err)
		}
	}
}

func TestConnectionDiagnosticsAreCountedAndRateLimited(t *testing.T) {
	s := testService(t)
	seed(t, s)
	for range 50 {
		s.engine.failure("in", "混淆握手失败")
	}
	s.engine.failure("in", "重复握手")
	counts := s.engine.snapshot()["in"].(map[string]any)["failures"].(map[string]uint64)
	if counts["混淆握手失败"] != 50 || counts["重复握手"] != 1 || len(s.events) != 1 {
		t.Fatal("unbounded or missing diagnostics", counts, len(s.events))
	}
	body, _ := json.Marshal(s.events)
	if strings.Contains(string(body), s.config.Load().Credentials[0].Secret) {
		t.Fatal("diagnostics leaked secret")
	}
}

func TestConcurrentReconnectStability(t *testing.T) {
	s := testService(t)
	exit, requests := mockSOCKS(t, "ok", "")
	seed(t, s, exit)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-requests:
			}
		}
	}()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				client := connectTG(t, s)
				roundTrip(t, client, "ping", "ok:ping")
				client.Close()
			}
		}()
	}
	wg.Wait()
	until := time.Now().Add(2 * time.Second)
	for {
		s.engine.mu.Lock()
		pending, sessions := s.engine.pendingTotal, len(s.engine.sessions)
		s.engine.mu.Unlock()
		if pending == 0 && sessions == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("sessions or pending slots leaked", pending, sessions)
		}
		time.Sleep(time.Millisecond)
	}
}
