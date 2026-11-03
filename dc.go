package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

//go:embed dc-seeds.json
var bundledDCs []byte

type dcManifest struct {
	Generation int              `json:"generation"`
	Addresses  map[int][]string `json:"addresses"`
}

type dcDirectory struct {
	mu       sync.RWMutex
	manifest dcManifest
}

func parseDCManifest(data []byte) (dcManifest, error) {
	var m dcManifest
	if len(data) > 32768 || json.Unmarshal(data, &m) != nil || m.Generation < 1 || m.Generation > 1000000000 || len(m.Addresses) > 64 {
		return m, errors.New("DC 地址表格式或大小无效")
	}
	for _, dc := range []int{1, 2, 3, 4, 5, 203} {
		if len(m.Addresses[dc]) == 0 {
			return m, errors.New("DC 地址表不完整")
		}
	}
	for dc, addresses := range m.Addresses {
		if dc == 0 || dc > 999 || dc < -999 || len(addresses) == 0 || len(addresses) > 8 {
			return m, errors.New("DC 编号或地址数量无效")
		}
		seen := map[string]bool{}
		for _, address := range addresses {
			host, port, err := net.SplitHostPort(address)
			ip, ipErr := netip.ParseAddr(host)
			if err != nil || ipErr != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || port != "443" || seen[address] {
				return m, errors.New("DC 必须使用不重复的公网 IP 和 443 端口")
			}
			for _, block := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
				if netip.MustParsePrefix(block).Contains(ip) {
					return m, errors.New("DC 地址不能使用保留地址")
				}
			}
			seen[address] = true
		}
	}
	return m, nil
}

func newDCDirectory(store *Store) *dcDirectory {
	m, err := parseDCManifest(bundledDCs)
	if err != nil {
		panic(err)
	}
	var cached []byte
	if store != nil && store.db.QueryRow("SELECT body FROM dc_cache WHERE id=1").Scan(&cached) == nil {
		if next, err := parseDCManifest(cached); err == nil && next.Generation >= m.Generation {
			m = next
		}
	}
	return &dcDirectory{manifest: m}
}

func (d *dcDirectory) addresses(dc int) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	addresses := d.manifest.Addresses[dc]
	if len(addresses) == 0 && dc < 0 {
		addresses = d.manifest.Addresses[-dc]
	}
	return append([]string(nil), addresses...)
}

var seedDirectory = newDCDirectory(nil)

func dcAddresses(dc int) []string { return seedDirectory.addresses(dc) }

func (s *Service) refreshDCs(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://raw.githubusercontent.com/wstimin/tg-relay/main/dc-seeds.json", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("DC 地址源返回 HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil {
		return err
	}
	m, err := parseDCManifest(data)
	if err != nil {
		return err
	}
	s.dcs.mu.Lock()
	defer s.dcs.mu.Unlock()
	if m.Generation <= s.dcs.manifest.Generation {
		return nil
	}
	if _, err = s.store.db.Exec("INSERT INTO dc_cache(id,body) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", data); err != nil {
		return err
	}
	s.dcs.manifest = m
	return nil
}

func (s *Service) startDCUpdates() {
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			if err := s.refreshDCs(s.ctx, client); err != nil && s.ctx.Err() == nil {
				s.addEvent("warn", "DC 地址刷新失败", "继续使用已校验缓存或内置地址；TG 路由和出口不变")
			}
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Race bounded candidates through the same explicit exit; losing tunnels are always closed.
func (e *Engine) dialDC(ctx context.Context, exit Outbound, dc int) (net.Conn, error) {
	addresses := e.s.dcs.addresses(dc)
	if len(addresses) == 0 {
		return nil, errors.New("未知 Telegram DC")
	}
	key := outboundFingerprint(&exit) + ":" + strconv.Itoa(dc)
	e.mu.Lock()
	preferred := e.preferredDC[key]
	e.mu.Unlock()
	for i, address := range addresses {
		if address == preferred {
			addresses[0], addresses[i] = addresses[i], addresses[0]
			break
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn    net.Conn
		address string
		err     error
	}
	results := make(chan result)
	for i, address := range addresses {
		go func() {
			if i > 0 {
				timer := time.NewTimer(time.Duration(i) * 200 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
			}
			attempt, stop := context.WithTimeout(ctx, 5*time.Second)
			conn, err := dialOutbound(attempt, exit, address)
			stop()
			select {
			case results <- result{conn: conn, address: address, err: err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	var last error
	for range addresses {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-results:
			if r.err == nil {
				e.mu.Lock()
				if len(e.preferredDC) >= 256 {
					clear(e.preferredDC)
				}
				e.preferredDC[key] = r.address
				e.mu.Unlock()
				return r.conn, nil
			}
			last = r.err
		}
	}
	return nil, last
}
