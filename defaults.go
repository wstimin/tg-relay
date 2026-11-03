package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func suggestInboundPort(ctx context.Context, c *Config, listenIP string) (int, error) {
	if net.ParseIP(listenIP) == nil {
		return 0, errors.New("监听 IP 无效，请填写本机 IP、0.0.0.0 或 ::")
	}
	configured := make(map[int]bool, len(c.Inbounds))
	for _, n := range c.Inbounds {
		configured[n.Port] = true
	}
	for range 32 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(listenIP, "0"))
		if err != nil {
			return 0, errors.New("无法在此监听 IP 检测端口，请确认该地址属于本机且允许监听")
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			return 0, err
		}
		if !configured[port] {
			return port, nil
		}
	}
	return 0, errors.New("暂未找到空闲 TCP 端口，请重试或手动填写")
}

func usablePublicHost(host string) bool {
	if !validHost(host) || strings.EqualFold(host, "localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	return strings.Contains(host, ".")
}

type inboundDefaults struct {
	mu      sync.Mutex
	host    string
	checked time.Time
	lookup  func(context.Context) (string, error)
}

func (d *inboundDefaults) detect(ctx context.Context, c *Config, panelHost string) (string, string, error) {
	for _, n := range c.Inbounds {
		if usablePublicHost(n.PublicHost) {
			return n.PublicHost, "已有入站的公开入口（请确认适用于当前服务器）", nil
		}
	}
	if usablePublicHost(panelHost) {
		return panelHost, "面板配置的访问地址（反向代理或 CDN 地址需手动核对）", nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.checked.IsZero() && time.Since(d.checked) < 10*time.Minute {
		if d.host != "" {
			return d.host, "服务器公网查询（ipify；多 IP / NAT 请核对）", nil
		}
		return "", "", errors.New("公网地址查询失败，请手动填写；稍后可重试")
	}
	host, err := d.lookup(ctx)
	d.checked = time.Now()
	d.host = ""
	if err != nil || !usablePublicHost(host) || net.ParseIP(host) == nil {
		return "", "", errors.New("无法识别服务器公网 IP，请手动填写可访问的 IP 或域名")
	}
	d.host = host
	return host, "服务器公网查询（ipify；多 IP / NAT 请核对）", nil
}
func lookupPublicIP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", errors.New("公网查询失败")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
