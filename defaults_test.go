package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

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
