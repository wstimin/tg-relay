package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDownloadUpdateProgressAndLimits(t *testing.T) {
	payload := strings.Repeat("release", 10000)
	for _, known := range []bool{true, false} {
		t.Run(fmt.Sprint("known-length-", known), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if known {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
				} else {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(payload))
			}))
			defer server.Close()
			var last, total int64
			calls := 0
			data, err := downloadUpdate(context.Background(), server.Client(), server.URL, int64(len(payload)), func(n, size int64) {
				if n < last || n > int64(len(payload)) {
					t.Fatalf("invalid progress: %d", n)
				}
				last, total = n, size
				calls++
			})
			if err != nil || string(data) != payload || calls == 0 || last != int64(len(payload)) {
				t.Fatalf("download: %v, %d/%d", err, last, total)
			}
			if (known && total != int64(len(payload))) || (!known && total != 0) {
				t.Fatalf("invented content length: %d", total)
			}
			if _, err := downloadUpdate(context.Background(), server.Client(), server.URL, 20, nil); err == nil {
				t.Fatal("oversized download accepted")
			}
		})
	}
}

func TestUpdateProgressSurvivesRestart(t *testing.T) {
	a := newAPI(testService(t), "", false)
	a.updater.dir = t.TempDir()
	for _, phase := range []string{"queued", "downloading", "verifying", "installing", "restarting", "validating", "complete", "failed"} {
		p := updateProgress{Phase: phase, Target: "v0.4.2", At: time.Now(), Downloaded: 50, Total: 100}
		if err := writeUpdateStatus(a.updater.dir, p); err != nil {
			t.Fatal(err)
		}
		if got := a.updater.progress(); got.Phase != phase || got.Downloaded != 50 || got.Total != 100 {
			t.Fatalf("lost status: %+v", got)
		}
		if updateActive(p) != (phase != "complete" && phase != "failed") {
			t.Fatalf("active phase: %s", phase)
		}
		response := requestAPI(a, "GET", "/api/auth", "", nil)
		var auth struct {
			UpdatePhase  string `json:"updatePhase"`
			UpdateTarget string `json:"updateTarget"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &auth); err != nil || auth.UpdatePhase != phase || auth.UpdateTarget != p.Target {
			t.Fatal(response.Body.String(), err)
		}
	}
}

func TestVersionOrdering(t *testing.T) {
	for _, item := range []struct {
		next, current string
		want          bool
	}{
		{"v0.10.0", "v0.9.9", true}, {"v1.0.0", "v0.99.99", true}, {"v0.4.1", "v0.4.0", true},
		{"v0.4.0", "v0.4.0", false}, {"v0.3.9", "v0.4.0", false}, {"v0.5.0-rc1", "v0.4.0", false}, {"v01.0.0", "v0.4.0", false}, {"v1.0.0", "dev", false}, {"../../bin/sh", "v0.4.0", false},
	} {
		if newerVersion(item.next, item.current) != item.want {
			t.Fatalf("%s vs %s", item.next, item.current)
		}
	}
}

func updateArchive(t *testing.T, extra string, kind byte) ([]byte, []byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name := range updateFiles {
		data := []byte("release " + name)
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0644, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if extra != "" {
		if err := tw.WriteHeader(&tar.Header{Name: extra, Typeflag: kind, Mode: 0644, Linkname: "/etc/passwd"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	sum := sha256.Sum256(data)
	return data, []byte(fmt.Sprintf("%x  tg-relay-linux-amd64.tar.gz\n", sum))
}

func TestUpdateArchiveTrustBoundary(t *testing.T) {
	data, sums := updateArchive(t, "", 0)
	if files, err := verifiedUpdateArchive(data, sums, "tg-relay-linux-amd64.tar.gz", ""); err != nil || len(files) != len(updateFiles) {
		t.Fatalf("valid archive: %v", err)
	}
	if _, err := verifiedUpdateArchive(append(data, 1), sums, "tg-relay-linux-amd64.tar.gz", ""); err == nil {
		t.Fatal("tampering accepted")
	}
	if _, err := verifiedUpdateArchive(data, sums, "tg-relay-linux-amd64.tar.gz", "sha256:wrong"); err == nil {
		t.Fatal("metadata digest mismatch accepted")
	}
	if _, err := verifiedUpdateArchive(data, append(sums, sums...), "tg-relay-linux-amd64.tar.gz", ""); err == nil {
		t.Fatal("duplicate hash accepted")
	}
	for _, item := range []struct {
		name string
		kind byte
	}{{"../etc/passwd", tar.TypeReg}, {"tg-relay", tar.TypeSymlink}, {"tg-relay", tar.TypeReg}, {"unexpected", tar.TypeReg}} {
		data, sums := updateArchive(t, item.name, item.kind)
		if _, err := verifiedUpdateArchive(data, sums, "tg-relay-linux-amd64.tar.gz", ""); err == nil {
			t.Fatalf("unsafe archive accepted: %s", item.name)
		}
	}
}

func TestUpdateAPIConfirmationLockAndFailures(t *testing.T) {
	previous := buildVersion
	buildVersion = "v0.4.0"
	defer func() { buildVersion = previous }()
	s := testService(t)
	a := newAPI(s, "", false)
	dir := t.TempDir()
	calls := 0
	a.updater = &panelUpdater{dir: dir, enabled: true, fetch: func(context.Context) (releaseInfo, error) {
		calls++
		return releaseInfo{Tag: "v0.5.0", Body: "release notes"}, nil
	}}
	if got := requestAPI(a, "GET", "/api/update", "", nil); got.Code != 401 {
		t.Fatal("update metadata unauthenticated")
	}
	login := requestAPI(a, "POST", "/api/setup", `{"username":"admin","password":"123456"}`, nil)
	cookies := login.Result().Cookies()
	post := func(body string) int { return requestAPI(a, "POST", "/api/update", body, cookies).Code }
	if post(`{"version":"v0.5.0","confirm":true}`) == 200 {
		t.Fatal("unchecked update accepted")
	}
	checked := requestAPI(a, "POST", "/api/update/check", "", cookies)
	if checked.Code != 200 || !strings.Contains(checked.Body.String(), `"available":true`) {
		t.Fatal(checked.Body.String())
	}
	_ = requestAPI(a, "POST", "/api/update/check", "", cookies)
	if calls != 1 {
		t.Fatal("check cache bypassed")
	}
	for _, body := range []string{`{"version":"v0.5.0","confirm":false}`, `{"version":"v0.3.0","confirm":true}`, `{"version":"v0.6.0","confirm":true}`} {
		if post(body) == 200 {
			t.Fatal("invalid request accepted")
		}
	}
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for range 2 {
		wg.Go(func() { results <- post(`{"version":"v0.5.0","confirm":true}`) })
	}
	wg.Wait()
	close(results)
	success := 0
	for code := range results {
		if code == 200 {
			success++
		}
	}
	if success != 1 {
		t.Fatal("duplicate update queued")
	}
	data, err := os.ReadFile(filepath.Join(dir, "update-request"))
	if err != nil || string(data) != "v0.5.0" {
		t.Fatalf("request: %s %v", data, err)
	}
	if a.updater.progress().Phase != "queued" {
		t.Fatal("queue status missing")
	}
	_ = os.Remove(filepath.Join(dir, "update-request"))
	_ = writeUpdateStatus(dir, updateProgress{Phase: "failed", At: time.Now()})
	a.updater.checked = time.Now().Add(-time.Hour)
	a.updater.fetch = func(context.Context) (releaseInfo, error) { return releaseInfo{}, errors.New("network failed") }
	failed := requestAPI(a, "POST", "/api/update/check", "", cookies)
	if !strings.Contains(failed.Body.String(), "network failed") || post(`{"version":"v0.5.0","confirm":true}`) == 200 {
		t.Fatal("failed check allowed update")
	}
	a.updater.enabled = false
	if post(`{"version":"v0.5.0","confirm":true}`) == 200 {
		t.Fatal("unmanaged deployment accepted")
	}
}

func TestVersionAndReadinessAPI(t *testing.T) {
	s := testService(t)
	a := newAPI(s, "", false)
	response := requestAPI(a, http.MethodGet, "/api/auth", "", nil)
	var info struct {
		Version string
		Ready   bool
	}
	if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil || info.Version != buildVersion || !info.Ready {
		t.Fatal(response.Body.String())
	}
}

func TestUpdateReplacementRollback(t *testing.T) {
	original := updateFiles
	defer func() { updateFiles = original }()
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			dir := t.TempDir()
			updateFiles = map[string]string{"tg-relay": filepath.Join(dir, "tg-relay"), "install.sh": filepath.Join(dir, "manage.sh")}
			old := map[string][]byte{"tg-relay": []byte("old core"), "install.sh": []byte("old menu")}
			next := map[string][]byte{"tg-relay": []byte("new core"), "install.sh": []byte("new menu")}
			for name, path := range updateFiles {
				if err := os.WriteFile(path, old[name], 0700); err != nil {
					t.Fatal(err)
				}
			}
			starts := 0
			err := replaceUpdateFiles(next, old, func() error { starts++; return nil }, func() error {
				if fail {
					return errors.New("startup failed")
				}
				return nil
			})
			want := next
			if fail {
				want = old
				if err == nil || !strings.Contains(err.Error(), "已恢复原程序") || starts != 2 {
					t.Fatalf("rollback: %v starts=%d", err, starts)
				}
			} else if err != nil || starts != 1 {
				t.Fatalf("commit: %v", err)
			}
			for name, path := range updateFiles {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want[name]) {
					t.Fatalf("%s: %s %v", name, got, err)
				}
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != len(updateFiles) {
				t.Fatal("temporary update files leaked")
			}
		})
	}
}
