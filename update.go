package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Release builds inject the tag. A local build must never masquerade as a release.
var buildVersion = "dev"

const releaseRepository = "https://github.com/wstimin/tg-relay"
const managedDataDir = "/var/lib/tg-relay"

var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

func newerVersion(next, current string) bool {
	a, b := versionPattern.FindStringSubmatch(next), versionPattern.FindStringSubmatch(current)
	if a == nil || b == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x > y
		}
	}
	return false
}

type releaseInfo struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Body       string `json:"body"`
	Assets     []struct {
		Name   string `json:"name"`
		Digest string `json:"digest"`
	} `json:"assets"`
}

func updateClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 5 {
			return errors.New("更新下载重定向无效")
		}
		host := req.URL.Hostname()
		if host != "github.com" && host != "api.github.com" && !strings.HasSuffix(host, ".githubusercontent.com") {
			return errors.New("更新下载来源无效")
		}
		return nil
	}}
}

func downloadUpdate(ctx context.Context, client *http.Client, address string, limit int64, progress func(int64, int64)) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TG-Relay-Update/"+buildVersion)
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("无法连接 GitHub 更新源，请检查服务器网络、DNS 或代理设置后重试")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub 更新源返回 HTTP %d，请稍后重试", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, errors.New("更新文件超过大小限制")
	}
	reader := io.LimitReader(response.Body, limit+1)
	var data []byte
	buffer := make([]byte, 32<<10)
	last := time.Time{}
	for {
		n, readErr := reader.Read(buffer)
		data = append(data, buffer[:n]...)
		if int64(len(data)) > limit {
			return nil, errors.New("更新文件超过大小限制")
		}
		if progress != nil && (time.Since(last) >= 250*time.Millisecond || readErr == io.EOF) {
			progress(int64(len(data)), max(response.ContentLength, 0))
			last = time.Now()
		}
		if readErr == io.EOF {
			return data, nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func latestRelease(ctx context.Context) (releaseInfo, error) {
	data, err := downloadUpdate(ctx, updateClient(12*time.Second), "https://api.github.com/repos/wstimin/tg-relay/releases/latest", 1<<20, nil)
	if err != nil {
		return releaseInfo{}, err
	}
	var release releaseInfo
	if err := json.Unmarshal(data, &release); err != nil {
		return release, errors.New("GitHub 版本信息格式无效")
	}
	if !versionPattern.MatchString(release.Tag) || release.Draft || release.Prerelease {
		return release, errors.New("未找到有效的正式版本")
	}
	return release, nil
}

type updateProgress struct {
	Phase      string    `json:"phase"`
	Target     string    `json:"target"`
	Message    string    `json:"message"`
	At         time.Time `json:"at"`
	Downloaded int64     `json:"downloaded,omitempty"`
	Total      int64     `json:"total,omitempty"`
}
type panelUpdater struct {
	mu         sync.Mutex
	dir        string
	enabled    bool
	release    releaseInfo
	checked    time.Time
	checkError string
	reason     string
	fetch      func(context.Context) (releaseInfo, error)
}

func newPanelUpdater(dir string, enabled bool) *panelUpdater {
	if dir != "" {
		dir = filepath.Clean(dir)
	}
	reason := ""
	switch {
	case runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64"):
		reason = "当前平台不支持 systemd 一键更新，请使用对应平台的发布包。"
	case !enabled:
		reason = "当前服务未启用 -managed-updates，通常是旧 systemd 服务文件未更新。请运行最新安装脚本，选择 1 修复更新组件，保留原配置。"
	case dir != managedDataDir:
		reason = "数据目录不是 /var/lib/tg-relay，无法使用托管更新；请核对 systemd 启动参数。"
	}
	return &panelUpdater{dir: dir, enabled: reason == "", reason: reason, fetch: latestRelease}
}
func (u *panelUpdater) progress() updateProgress {
	var status updateProgress
	if u.dir == "" {
		return status
	}
	file, err := os.Open(filepath.Join(u.dir, "update-status.json"))
	if err != nil {
		return status
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 16384))
	if err == nil && len(data) < 16384 {
		_ = json.Unmarshal(data, &status)
	}
	return status
}
func updateActive(p updateProgress) bool {
	return (p.Phase == "queued" || p.Phase == "downloading" || p.Phase == "verifying" || p.Phase == "installing" || p.Phase == "restarting" || p.Phase == "validating") && time.Since(p.At) < 10*time.Minute
}
func (a *API) serveUpdate(w http.ResponseWriter, r *http.Request) {
	u := a.updater
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case r.URL.Path == "/api/update" && r.Method == http.MethodGet:
	case r.URL.Path == "/api/update/check" && r.Method == http.MethodPost:
		if u.checked.IsZero() || time.Since(u.checked) >= 30*time.Second {
			release, err := u.fetch(r.Context())
			u.checked = time.Now().UTC()
			u.checkError = ""
			if err != nil {
				u.checkError = err.Error()
			} else {
				u.release = release
			}
		}
	case r.URL.Path == "/api/update" && r.Method == http.MethodPost:
		var input struct {
			Version string `json:"version"`
			Confirm bool   `json:"confirm"`
		}
		if err := readJSON(r, &input); err != nil {
			failChange(w, err)
			return
		}
		if !u.enabled {
			fail(w, 400, "此部署未启用面板更新，请先在服务器运行 tg 升级安装器")
			return
		}
		if !input.Confirm || input.Version != u.release.Tag || !newerVersion(input.Version, buildVersion) || u.checkError != "" || time.Since(u.checked) > 15*time.Minute {
			fail(w, 400, "请先检查新版并确认更新，禁止降级或安装未核对的版本")
			return
		}
		if updateActive(u.progress()) {
			fail(w, 409, "已有更新任务正在运行")
			return
		}
		if _, err := os.Stat(filepath.Join(u.dir, "update-request")); err == nil {
			fail(w, 409, "已有更新请求等待处理")
			return
		}
		status := updateProgress{Phase: "queued", Target: input.Version, Message: "等待更新服务；下载并校验完成后将重启，TG 连接会短暂断开", At: time.Now().UTC()}
		if err := writeUpdateStatus(u.dir, status); err != nil {
			failChange(w, err)
			return
		}
		if err := atomicUpdateFile(filepath.Join(u.dir, "update-request"), []byte(input.Version), 0600); err != nil {
			status.Phase = "failed"
			status.Message = err.Error()
			_ = writeUpdateStatus(u.dir, status)
			failChange(w, err)
			return
		}
		a.s.addEvent("info", "面板更新", "已确认更新至 "+input.Version)
	default:
		fail(w, 405, "更新接口或请求方式无效")
		return
	}
	reason := ""
	if !u.enabled {
		reason = u.reason
		if reason == "" {
			reason = "一键更新未启用，请运行最新安装脚本并选择 1 修复更新组件，保留原配置。"
		}
	}
	if buildVersion == "dev" {
		reason = "当前为本地开发构建，请通过正式发布包安装后使用一键更新。"
	}
	status := u.progress()
	if updateActive(status) && time.Since(status.At) > 5*time.Minute {
		status.Message = "更新耗时较长，请在服务器查看 journalctl -u tg-relay-update；不要重复提交。"
	}
	sendJSON(w, 200, map[string]any{"current": buildVersion, "latest": u.release.Tag, "available": newerVersion(u.release.Tag, buildVersion), "supported": u.enabled && buildVersion != "dev", "reason": reason, "checkedAt": u.checked, "error": u.checkError, "releaseURL": releaseRepository + "/releases/tag/" + u.release.Tag, "notes": u.release.Body, "progress": status})
}

func atomicUpdateFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".update-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}
func writeUpdateStatus(dir string, status updateProgress) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return atomicUpdateFile(filepath.Join(dir, "update-status.json"), data, 0644)
}

var updateFiles = map[string]string{
	"tg-relay": "/opt/tg-relay/tg-relay", "install.sh": "/opt/tg-relay/manage.sh", "LICENSE.mtg": "/opt/tg-relay/LICENSE.mtg", "THIRD_PARTY_NOTICES.md": "/opt/tg-relay/THIRD_PARTY_NOTICES.md",
	"tg-relay.service": "/etc/systemd/system/tg-relay.service", "tg-relay-renew.service": "/etc/systemd/system/tg-relay-renew.service", "tg-relay-renew.timer": "/etc/systemd/system/tg-relay-renew.timer", "tg-relay-update.service": "/etc/systemd/system/tg-relay-update.service", "tg-relay-update.path": "/etc/systemd/system/tg-relay-update.path",
}

func verifiedUpdateArchive(archive, sums []byte, asset, digest string) (map[string][]byte, error) {
	sum := sha256.Sum256(archive)
	actual := hex.EncodeToString(sum[:])
	expected := ""
	for _, line := range strings.Split(string(sums), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && strings.TrimPrefix(parts[1], "*") == asset {
			if expected != "" {
				return nil, errors.New("重复的安装包校验项")
			}
			expected = parts[0]
		}
	}
	if expected != actual || (digest != "" && digest != "sha256:"+actual) {
		return nil, errors.New("更新包 SHA256 校验失败，未修改程序")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if _, ok := updateFiles[h.Name]; !ok {
			return nil, fmt.Errorf("安装包含未允许文件：%s", h.Name)
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 64<<20 || files[h.Name] != nil {
			return nil, errors.New("安装包文件类型、大小或重复项无效")
		}
		data, err := io.ReadAll(io.LimitReader(reader, 64<<20+1))
		if err != nil {
			return nil, err
		}
		files[h.Name] = data
	}
	if len(files) != len(updateFiles) {
		return nil, errors.New("更新包文件不完整")
	}
	return files, nil
}

func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s 失败：%s", strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return nil
}

func waitUpdatedPanel(expected string) error {
	data, err := os.ReadFile("/etc/tg-relay/panel.conf")
	if err != nil {
		return err
	}
	settings := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			settings[key] = value
		}
	}
	address := settings["TG_RELAY_LISTEN"]
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	destination := net.JoinHostPort(host, port)
	scheme := "http"
	name := settings["TG_RELAY_ADMIN_HOST"]
	if name == "" {
		name = "localhost"
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, destination)
	}}
	defer transport.CloseIdleConnections()
	if settings["TG_RELAY_TLS_CERT"] != "" {
		scheme = "https"
		cert, err := os.ReadFile(settings["TG_RELAY_TLS_CERT"])
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cert) {
			return errors.New("面板证书格式无效")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	addressURL := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(name, port), Path: "/api/auth"}).String()
	for i := 0; i < 20; i++ {
		response, err := client.Get(addressURL)
		if err == nil {
			var auth struct {
				Version string `json:"version"`
				Ready   bool   `json:"ready"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&auth)
			response.Body.Close()
			if err == nil && response.StatusCode == 200 && auth.Version == expected && auth.Ready {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("新版面板或 TG 入站未能通过启动检查")
}

func applyManagedUpdate() (result error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("自动更新必须由 Linux root systemd 更新服务执行")
	}
	file, err := os.Open(managedDataDir + "/update-request")
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64))
	_ = file.Close()
	if err != nil {
		return err
	}
	if err = os.Remove(managedDataDir + "/update-request"); err != nil {
		return err
	}
	target := string(raw)
	progress := func(phase, message string) {
		_ = writeUpdateStatus(managedDataDir, updateProgress{Phase: phase, Target: target, Message: message, At: time.Now().UTC()})
	}
	defer func() {
		if result != nil {
			progress("failed", result.Error())
		}
	}()
	if !newerVersion(target, buildVersion) {
		return errors.New("更新版本无效或不是更高的正式版本")
	}
	progress("downloading", "正在从官方仓库下载并校验，当前 TG 服务继续运行")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	release, err := latestRelease(ctx)
	if err != nil {
		return err
	}
	if release.Tag != target {
		return errors.New("最新版本已变化，请重新检查后更新")
	}
	asset := "tg-relay-linux-" + runtime.GOARCH + ".tar.gz"
	digest := ""
	found := false
	for _, a := range release.Assets {
		if a.Name == asset {
			digest = a.Digest
			found = true
		}
	}
	if !found {
		return errors.New("正式版本未提供当前架构安装包")
	}
	base := releaseRepository + "/releases/download/" + target + "/"
	client := updateClient(150 * time.Second)
	archive, err := downloadUpdate(ctx, client, base+asset, 32<<20, func(downloaded, total int64) {
		_ = writeUpdateStatus(managedDataDir, updateProgress{Phase: "downloading", Target: target, Message: "正在下载安装包，当前 TG 服务继续运行", At: time.Now().UTC(), Downloaded: downloaded, Total: total})
	})
	if err != nil {
		return err
	}
	progress("verifying", "安装包下载完成，正在校验 SHA256、文件内容和程序版本")
	sums, err := downloadUpdate(ctx, client, base+"SHA256SUMS", 16384, nil)
	if err != nil {
		return err
	}
	files, err := verifiedUpdateArchive(archive, sums, asset, digest)
	if err != nil {
		return err
	}
	// Temporary rollback state lives only for this transaction and is removed on return.
	previous := map[string][]byte{}
	for name, path := range updateFiles {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("安装文件不存在或不是普通文件：%s，请先运行 tg 修复安装", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		previous[name] = data
	}
	stage, err := os.MkdirTemp("/opt/tg-relay", ".update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	binary := filepath.Join(stage, "tg-relay")
	if err = os.WriteFile(binary, files["tg-relay"], 0700); err != nil {
		return err
	}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	output, err := exec.CommandContext(checkCtx, binary, "-version").Output()
	checkCancel()
	if err != nil || strings.TrimSpace(string(output)) != target {
		return errors.New("新程序版本或架构校验失败")
	}
	progress("installing", "校验通过，正在重启服务；TG 连接将短暂断开，完成后需要重新登录")
	if err = runSystemctl("stop", "tg-relay.service"); err != nil {
		return err
	}
	err = replaceUpdateFiles(files, previous, func() error {
		progress("restarting", "正在启动服务，页面会自动等待恢复；TG 链接不变")
		if err := runSystemctl("daemon-reload"); err != nil {
			return err
		}
		return runSystemctl("restart", "tg-relay.service")
	}, func() error {
		progress("validating", "服务已启动，正在确认版本、面板响应和入站监听")
		if err := waitUpdatedPanel(target); err != nil {
			return err
		}
		return atomicUpdateFile("/opt/tg-relay/version", []byte(target+"\n"), 0644)
	})
	if err != nil {
		return err
	}
	progress("complete", "更新完成，当前版本 "+target+"；请重新登录面板")
	return nil
}
func replaceUpdateFiles(files, previous map[string][]byte, activate, validate func() error) (result error) {
	committed := false
	defer func() {
		if committed {
			return
		}
		var rollbackErrors []error
		for name, path := range updateFiles {
			if err := atomicUpdateFile(path, previous[name], updateFileMode(name)); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
		rollbackErrors = append(rollbackErrors, activate())
		if err := errors.Join(rollbackErrors...); err != nil {
			result = errors.Join(result, fmt.Errorf("恢复原程序失败，请运行 tg 检查服务：%w", err))
		} else {
			result = errors.Join(result, errors.New("已恢复原程序并重新启动服务"))
		}
	}()
	for name, path := range updateFiles {
		if err := atomicUpdateFile(path, files[name], updateFileMode(name)); err != nil {
			return err
		}
	}
	if err := activate(); err != nil {
		return err
	}
	if err := validate(); err != nil {
		return err
	}
	committed = true
	return nil
}
func updateFileMode(name string) os.FileMode {
	if name == "tg-relay" || name == "install.sh" {
		return 0755
	}
	return 0644
}
