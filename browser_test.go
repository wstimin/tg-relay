package main

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sync"
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
	updateFixture := os.Getenv("TGRELAY_UI_TEST_UPDATE") == "1"
	if updateFixture {
		a.updater = &panelUpdater{dir: t.TempDir(), enabled: true, fetch: func(context.Context) (releaseInfo, error) { return releaseInfo{Tag: "v0.4.2"}, nil }}
	}
	a.entryDefaults = &inboundDefaults{lookup: func(context.Context) (string, error) { return "203.0.113.10", nil }}
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
	var updateMu sync.Mutex
	updateRunning, restarted := false, false
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		updateMu.Lock()
		isRestarted := restarted
		updateMu.Unlock()
		if updateFixture && isRestarted {
			p := a.updater.progress()
			if r.URL.Path == "/api/auth" {
				sendJSON(w, 200, map[string]any{"initialized": true, "authenticated": false, "version": "v0.4.2", "ready": p.Phase == "complete", "updatePhase": p.Phase, "updateTarget": p.Target})
				return
			}
			fail(w, 401, "测试夹具：模拟重启后会话失效")
			return
		}
		r.AddCookie(cookie)
		a.ServeHTTP(w, r)
		if updateFixture && r.URL.Path == "/api/update" && r.Method == "POST" && a.updater.progress().Phase == "queued" {
			updateMu.Lock()
			start := !updateRunning
			updateRunning = true
			updateMu.Unlock()
			if start {
				go func() {
					// UI-only restart simulation; never compiled into the application.
					for _, phase := range []string{"queued", "downloading", "verifying", "installing", "validating", "complete"} {
						time.Sleep(2 * time.Second)
						_ = writeUpdateStatus(a.updater.dir, updateProgress{Phase: phase, Target: "v0.4.2", Message: "浏览器测试夹具：模拟更新阶段，不代表真实发布下载", At: time.Now().UTC(), Downloaded: 50, Total: 100})
						if phase == "validating" {
							updateMu.Lock()
							restarted = true
							updateMu.Unlock()
						}
					}
				}()
			}
		}
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
