package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestInboundPortDetection(t *testing.T) {
	s := testService(t)
	a := newAPI(s, "", false)
	if r := requestAPI(a, "GET", "/api/inbound-port", "", nil); r.Code != 401 {
		t.Fatalf("unauthenticated port detection: %d", r.Code)
	}
	cookies := requestAPI(a, "POST", "/api/setup", `{"username":"admin","password":"123456"}`, nil).Result().Cookies()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	configured := busy.Addr().(*net.TCPAddr).Port
	c := &Config{Inbounds: []Inbound{{Port: configured, Enabled: false}}}
	for _, ip := range []string{"127.0.0.1", "0.0.0.0"} {
		port, err := suggestInboundPort(context.Background(), c, ip)
		if err != nil || port == configured || port < 1 || port > 65535 {
			t.Fatalf("port %d: %v", port, err)
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("suggested port unavailable: %v", err)
		}
		listener.Close()
	}
	revision := s.config.Load().Revision
	response := requestAPI(a, "GET", "/api/inbound-port?listenIP=127.0.0.1", "", cookies)
	var result struct {
		Port     int    `json:"port"`
		ListenIP string `json:"listenIP"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Port == configured || result.Port == 0 || result.ListenIP != "127.0.0.1" {
		t.Fatal(response.Body.String())
	}
	if s.config.Load().Revision != revision {
		t.Fatal("port detection modified configuration")
	}
	claimed, err := net.Listen("tcp", net.JoinHostPort(result.ListenIP, strconv.Itoa(result.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer claimed.Close()
	body := fmt.Sprintf(`{"name":"suggested","listenIP":"127.0.0.1","port":%d,"publicHost":"relay.example.com","tlsDomain":"www.apple.com","enabled":true,"initialRoute":{"direct":true}}`, result.Port)
	if r := requestAPI(a, "POST", "/api/inbounds", body, cookies); r.Code != 400 || !strings.Contains(r.Body.String(), "占用") {
		t.Fatal("port claimed after detection must fail save", r.Code, r.Body.String())
	}
	if s.config.Load().Revision != revision || len(s.config.Load().Inbounds) != 0 || len(s.config.Load().Routes) != 0 {
		t.Fatal("failed bind saved partial configuration")
	}
	claimed.Close()
	if r := requestAPI(a, "POST", "/api/inbounds", body, cookies); r.Code != 200 {
		t.Fatal("available port could not be saved", r.Body.String())
	}
	for _, ip := range []string{"localhost", "invalid", "203.0.113.199"} {
		if r := requestAPI(a, "GET", "/api/inbound-port?listenIP="+ip, "", cookies); r.Code != 400 {
			t.Fatalf("invalid IP %s: %d", ip, r.Code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := suggestInboundPort(ctx, c, "127.0.0.1"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored", err)
	}
}

func TestInboundAddressDetection(t *testing.T) {
	calls := 0
	d := &inboundDefaults{lookup: func(context.Context) (string, error) { calls++; return "8.8.8.8", nil }}
	c := &Config{Inbounds: []Inbound{{PublicHost: "127.0.0.1"}, {PublicHost: "relay.example.com"}}}
	host, source, err := d.detect(context.Background(), c, "panel.example.com")
	if err != nil || host != "relay.example.com" || !strings.Contains(source, "已有入站") || calls != 0 {
		t.Fatal(host, source, err)
	}
	c.Inbounds = nil
	host, _, err = d.detect(context.Background(), c, "panel.example.com")
	if err != nil || host != "panel.example.com" || calls != 0 {
		t.Fatal(host, err)
	}
	for range 2 {
		host, _, err = d.detect(context.Background(), c, "localhost")
		if err != nil || host != "8.8.8.8" {
			t.Fatal(host, err)
		}
	}
	if calls != 1 {
		t.Fatal("public lookup cache bypassed")
	}
	for _, host := range []string{"localhost", "127.0.0.1", "10.0.0.1", "0.0.0.0", "::1", "http://example.com", "example.com:443", "fe80::1"} {
		if usablePublicHost(host) {
			t.Fatal("invalid public host accepted:", host)
		}
	}
	d = &inboundDefaults{lookup: func(context.Context) (string, error) { return "", errors.New("offline") }}
	if _, _, err := d.detect(context.Background(), c, ""); err == nil {
		t.Fatal("lookup failure hidden")
	}
}

func TestTLSPresetValidationAndPersistence(t *testing.T) {
	s := testService(t)
	a := newAPI(s, "", false)
	login := requestAPI(a, "POST", "/api/setup", `{"username":"admin","password":"123456"}`, nil)
	cookies := login.Result().Cookies()
	response := requestAPI(a, "PATCH", "/api/settings", `{"workspace":"Presets","tlsDomains":["www.apple.com","www.cloudflare.com"]}`, cookies)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	stored, _, _, err := s.store.load()
	if err != nil || len(stored.Settings.TLSDomains) != 2 {
		t.Fatal("presets not persisted", err)
	}
	response = requestAPI(a, "PATCH", "/api/settings", `{"workspace":"Renamed"}`, cookies)
	if response.Code != 200 || len(s.config.Load().Settings.TLSDomains) != 2 {
		t.Fatal("workspace edit removed presets")
	}
	for _, domains := range []string{`["1.1.1.1"]`, `["https://www.apple.com"]`, `["www.apple.com:443"]`, `["www.apple.com","WWW.APPLE.COM"]`, `["localhost"]`} {
		response = requestAPI(a, "PATCH", "/api/settings", `{"workspace":"Invalid","tlsDomains":`+domains+`}`, cookies)
		if response.Code == 200 || s.config.Load().Settings.Workspace != "Renamed" {
			t.Fatal("invalid presets accepted")
		}
	}
}
