package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExplicitDirectRoute(t *testing.T) {
	s := testService(t)
	seed(t, s)
	if err := s.update(func(c *Config) error {
		c.Routes = []Route{{ID: "direct", Name: "直连", InboundIDs: []string{"in"}, Direct: true, Enabled: true}}
		return nil
	}, false); err != nil {
		t.Fatal(err)
	}
	c := s.config.Load()
	_, exit, err := c.resolve("in")
	if err != nil || exit.Type != "DIRECT" {
		t.Fatalf("direct route: %v %v", exit, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.CopyN(conn, conn, 4)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialOutbound(ctx, *exit, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "ping", "ping")
	bad := cloneConfig(c)
	bad.Routes[0].OutboundID = "missing"
	if validateConfig(bad) == nil {
		t.Fatal("ambiguous direct+outbound route accepted")
	}
	bad.Routes[0].Direct = false
	if validateConfig(bad) == nil {
		t.Fatal("missing outbound accepted")
	}
}

func TestCreateInboundWithAtomicRoute(t *testing.T) {
	for _, target := range []string{`{"direct":true,"outboundID":""}`, `{"direct":false,"outboundID":"exit"}`} {
		t.Run(target, func(t *testing.T) {
			s := testService(t)
			if strings.Contains(target, `"direct":true`) {
				seed(t, s)
			} else {
				exit, _ := mockSOCKS(t, "exit", "")
				seed(t, s, exit)
			}
			a := newAPI(s, "", false)
			login := requestAPI(a, "POST", "/api/setup", `{"username":"admin","password":"123456"}`, nil)
			cookies := login.Result().Cookies()
			body := fmt.Sprintf(`{"name":"新入口","listenIP":"127.0.0.1","port":%d,"publicHost":"relay.example.com","tlsDomain":"www.apple.com","enabled":true,"initialRoute":%s}`, freePort(t), target)
			response := requestAPI(a, "POST", "/api/inbounds", body, cookies)
			if response.Code != 200 {
				t.Fatal(response.Body.String())
			}
			c := s.config.Load()
			n := &c.Inbounds[len(c.Inbounds)-1]
			r, o, err := c.resolve(n.ID)
			if err != nil || r == nil || o == nil {
				t.Fatalf("route missing: %v", err)
			}
			if r.Direct != strings.Contains(target, `"direct":true`) {
				t.Fatal("wrong target")
			}
			before := c.Revision
			bad := strings.Replace(body, target, `{"direct":false,"outboundID":"missing"}`, 1)
			response = requestAPI(a, "POST", "/api/inbounds", bad, cookies)
			if response.Code == 200 || s.config.Load().Revision != before {
				t.Fatal("failed creation modified config")
			}
		})
	}
}

func TestLinkWarningsAndStableDirectSwitch(t *testing.T) {
	s := testService(t)
	seed(t, s)
	a := newAPI(s, "", false)
	login := requestAPI(a, "POST", "/api/setup", `{"username":"admin","password":"123456"}`, nil)
	cookies := login.Result().Cookies()
	read := func() struct {
		Link, WebLink string
		Warnings      []string
	} {
		t.Helper()
		response := requestAPI(a, "GET", "/api/credentials/credential/link", "", cookies)
		var result struct {
			Link, WebLink string
			Warnings      []string
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil {
			t.Fatal(response.Body.String())
		}
		return result
	}
	before := read()
	if !strings.Contains(strings.Join(before.Warnings, " "), "没有匹配") {
		t.Fatal("missing route not explained")
	}
	parsed, err := url.Parse(before.Link)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := hex.DecodeString(parsed.Query().Get("secret"))
	if err != nil || secret[0] != 0xee || hex.EncodeToString(secret[1:17]) != s.config.Load().Credentials[0].Secret || string(secret[17:]) != s.config.Load().Inbounds[0].TLSDomain {
		t.Fatal("invalid Fake TLS secret encoding")
	}
	if before.WebLink != "https://t.me/proxy?"+parsed.RawQuery {
		t.Fatal("inconsistent web link")
	}
	if err := s.update(func(c *Config) error {
		c.Routes = []Route{{ID: "route", Name: "直连", InboundIDs: []string{"in"}, Direct: true, Enabled: true}}
		return nil
	}, false); err != nil {
		t.Fatal(err)
	}
	after := read()
	if before.Link != after.Link || strings.Contains(strings.Join(after.Warnings, " "), "没有匹配") {
		t.Fatal("direct switch changed link or warnings are stale")
	}
	response := requestAPI(a, "POST", "/api/inbounds/missing/test", "", cookies)
	if response.Code == 200 {
		t.Fatal("missing inbound probe accepted")
	}
}

func TestInboundProbeUsesMatchedExit(t *testing.T) {
	s := testService(t)
	exit, requests := mockSOCKS(t, "exit", "")
	seed(t, s, exit)
	checks, err := s.probeInbound("in")
	if err != nil || len(checks) != 2 || !checks[0].Healthy || !checks[1].Healthy {
		t.Fatalf("probe: %v %v", checks, err)
	}
	for _, target := range []string{dcAddresses(2)[0], "storage.googleapis.com:443"} {
		select {
		case got := <-requests:
			if got != target {
				t.Fatalf("got %s want %s", got, target)
			}
		case <-time.After(time.Second):
			t.Fatal("probe bypassed matched exit")
		}
	}
}

func TestSwitchToDirectRespectsModeAndFailClosed(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		t.Run(fmt.Sprint(immediate), func(t *testing.T) {
			s := testService(t)
			exit, _ := mockSOCKS(t, "exit", "")
			seed(t, s, exit)
			conn := connectTG(t, s)
			roundTrip(t, conn, "before", "exit:before")
			if err := s.update(func(c *Config) error {
				c.Routes[0].Direct = true
				c.Routes[0].OutboundID = ""
				return nil
			}, immediate); err != nil {
				t.Fatal(err)
			}
			if immediate {
				assertClosed(t, conn)
			} else {
				roundTrip(t, conn, "after", "exit:after")
			}
		})
	}
	c := &Config{Outbounds: []Outbound{{ID: "disabled"}}, Routes: []Route{
		{ID: "exit", InboundIDs: []string{"in"}, OutboundID: "disabled", Enabled: true, Priority: 1},
		{ID: "direct", InboundIDs: []string{"in"}, Direct: true, Enabled: true, Priority: 2},
	}}
	if _, _, err := c.resolve("in"); err == nil {
		t.Fatal("failed exit fell through to direct")
	}
}
