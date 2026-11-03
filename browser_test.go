package main

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// Opt-in browser fixture: loopback only, temporary database, never compiled into the application.
func TestBrowserHarness(t *testing.T) {
	address := os.Getenv("TGRELAY_UI_TEST_ADDR")
	if address == "" {
		t.Skip("browser fixture not requested")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("browser fixture must bind loopback")
	}
	s := testService(t)
	exit, _ := mockSOCKS(t, "本地模拟出口", "")
	seed(t, s, exit)
	if err := s.update(func(c *Config) error { c.Settings.Workspace = "浏览器验证实例"; return nil }, false); err != nil {
		t.Fatal(err)
	}
	a := newAPI(s, "", false)
	setup := requestAPI(a, "POST", "/api/setup", `{"username":"admin","password":"test-password-12345"}`, nil)
	if setup.Code != 200 {
		t.Fatal(setup.Body.String())
	}
	cookie := setup.Result().Cookies()[0]
	web, err := fs.Sub(assets, "web")
	if err != nil {
		t.Fatal(err)
	}
	files := http.FileServer(http.FS(web))
	stop := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(cookie)
		a.ServeHTTP(w, r)
	})
	mux.HandleFunc("/__test/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		select {
		case stop <- struct{}{}:
		default:
		}
	})
	mux.Handle("/", files)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener)
	t.Log("temporary browser fixture:", listener.Addr())
	select {
	case <-stop:
	case <-time.After(10 * time.Minute):
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Error(err)
	}
}
