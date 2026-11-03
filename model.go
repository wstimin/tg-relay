package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Inbound struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ListenIP   string `json:"listenIP"`
	Port       int    `json:"port"`
	PublicHost string `json:"publicHost"`
	TLSDomain  string `json:"tlsDomain"`
	Enabled    bool   `json:"enabled"`
}
type Outbound struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Account     string `json:"account"`
	Password    string `json:"password,omitempty"`
	HasPassword bool   `json:"hasPassword,omitempty"`
	Enabled     bool   `json:"enabled"`
}
type Route struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	InboundIDs []string `json:"inboundIDs"`
	OutboundID string   `json:"outboundID"`
	Direct     bool     `json:"direct"`
	Priority   int      `json:"priority"`
	Enabled    bool     `json:"enabled"`
}
type User struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	QuotaBytes int64  `json:"quotaBytes"`
	Expires    string `json:"expires"`
	Enabled    bool   `json:"enabled"`
}
type Credential struct {
	ID        string `json:"id"`
	InboundID string `json:"inboundID"`
	UserID    string `json:"userID"`
	Secret    string `json:"secret,omitempty"`
	Enabled   bool   `json:"enabled"`
}
type Settings struct {
	Workspace string `json:"workspace"`
}
type Config struct {
	Revision    int64        `json:"revision"`
	Inbounds    []Inbound    `json:"inbounds"`
	Outbounds   []Outbound   `json:"outbounds"`
	Routes      []Route      `json:"routes"`
	Users       []User       `json:"users"`
	Credentials []Credential `json:"credentials"`
	Settings    Settings     `json:"settings"`
}
type Usage struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

func (u Usage) Total() int64 { return u.Upload + u.Download }

type Event struct {
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`
	Title  string    `json:"title"`
	Detail string    `json:"detail"`
}
type Health struct {
	Healthy   bool      `json:"healthy"`
	LatencyMS int64     `json:"latencyMS"`
	Error     string    `json:"error,omitempty"`
	TestedAt  time.Time `json:"testedAt"`
}

func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func newSecret() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func cloneConfig(c *Config) *Config {
	b, _ := json.Marshal(c)
	var dst Config
	_ = json.Unmarshal(b, &dst)
	return &dst
}
func (c *Config) inbound(id string) *Inbound {
	for i := range c.Inbounds {
		if c.Inbounds[i].ID == id {
			return &c.Inbounds[i]
		}
	}
	return nil
}
func (c *Config) outbound(id string) *Outbound {
	for i := range c.Outbounds {
		if c.Outbounds[i].ID == id {
			return &c.Outbounds[i]
		}
	}
	return nil
}
func (c *Config) user(id string) *User {
	for i := range c.Users {
		if c.Users[i].ID == id {
			return &c.Users[i]
		}
	}
	return nil
}
func (c *Config) credential(id string) *Credential {
	for i := range c.Credentials {
		if c.Credentials[i].ID == id {
			return &c.Credentials[i]
		}
	}
	return nil
}

// Rules are ordered explicitly; an unusable matched exit never falls through to another exit.
func (c *Config) resolve(inboundID string) (*Route, *Outbound, error) {
	ordered := append([]Route(nil), c.Routes...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority == ordered[j].Priority {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Priority < ordered[j].Priority
	})
	for i := range ordered {
		r := &ordered[i]
		if !r.Enabled {
			continue
		}
		for _, id := range r.InboundIDs {
			if id != inboundID {
				continue
			}
			if r.Direct {
				return r, &Outbound{ID: "@direct", Name: "直连 Telegram", Type: "DIRECT", Enabled: true}, nil
			}
			o := c.outbound(r.OutboundID)
			if o == nil || !o.Enabled {
				return r, nil, errors.New("匹配路由的落地出口已停用")
			}
			return r, o, nil
		}
	}
	return nil, nil, errors.New("此入站没有匹配的启用路由")
}
func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 || host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
func validateConfig(c *Config) error {
	if len(c.Inbounds) > 256 || len(c.Users) > 10000 || len(c.Routes) > 1024 || len(c.Outbounds) > 1024 || len(c.Credentials) > 20000 {
		return errors.New("配置数量超过此版本的限制")
	}
	ids := map[string]bool{}
	check := func(id, name string) error {
		if id == "" || ids[id] {
			return errors.New("配置编号为空或重复")
		}
		ids[id] = true
		if strings.TrimSpace(name) == "" || len([]rune(name)) > 80 {
			return errors.New("名称不能为空或超过 80 个字符")
		}
		return nil
	}
	addresses := map[string]bool{}
	for _, n := range c.Inbounds {
		if err := check(n.ID, n.Name); err != nil {
			return err
		}
		if net.ParseIP(n.ListenIP) == nil || n.Port < 1 || n.Port > 65535 || !validHost(n.PublicHost) || !validHost(n.TLSDomain) || net.ParseIP(n.TLSDomain) != nil {
			return fmt.Errorf("入站 %s 的地址、端口或 TLS 域名无效", n.Name)
		}
		addr := net.JoinHostPort(n.ListenIP, fmt.Sprint(n.Port))
		if n.Enabled && addresses[addr] {
			return errors.New("启用的入站监听地址重复")
		}
		if n.Enabled {
			addresses[addr] = true
		}
	}
	for _, o := range c.Outbounds {
		if err := check(o.ID, o.Name); err != nil {
			return err
		}
		if o.ID == "@direct" {
			return errors.New("出口编号为系统保留值")
		}
		if (o.Type != "SOCKS5" && o.Type != "HTTP" && o.Type != "HTTPS") || !validHost(o.Host) || o.Port < 1 || o.Port > 65535 {
			return fmt.Errorf("出口 %s 的协议、地址或端口无效", o.Name)
		}
		if len(o.Account) > 255 || len(o.Password) > 255 || strings.ContainsAny(o.Account+o.Password, "\r\n") {
			return errors.New("落地认证信息无效")
		}
	}
	for _, u := range c.Users {
		if err := check(u.ID, u.Name); err != nil {
			return err
		}
		if u.QuotaBytes < 0 || u.QuotaBytes > 1<<50 {
			return errors.New("流量额度无效")
		}
		if u.Expires != "" {
			if _, err := time.Parse(time.RFC3339, u.Expires); err != nil {
				return errors.New("到期时间必须使用带时区的日期时间")
			}
		}
	}
	for _, r := range c.Routes {
		if err := check(r.ID, r.Name); err != nil {
			return err
		}
		if (r.Direct && r.OutboundID != "") || (!r.Direct && c.outbound(r.OutboundID) == nil) || len(r.InboundIDs) == 0 || r.Priority < 0 || r.Priority > 1000000 {
			return errors.New("路由必须指定有效入站、优先级，并在直连与落地出口中选择一种")
		}
		seen := map[string]bool{}
		for _, id := range r.InboundIDs {
			if c.inbound(id) == nil || seen[id] {
				return errors.New("路由包含不存在或重复的入站")
			}
			seen[id] = true
		}
	}
	counts := map[string]int{}
	members := map[string]bool{}
	for _, cr := range c.Credentials {
		if err := check(cr.ID, "凭据"); err != nil {
			return err
		}
		if c.inbound(cr.InboundID) == nil || c.user(cr.UserID) == nil {
			return errors.New("凭据引用了不存在的入站或用户")
		}
		key, err := hex.DecodeString(cr.Secret)
		if err != nil || len(key) != 16 {
			return errors.New("用户密钥无效")
		}
		member := cr.InboundID + ":" + cr.UserID
		if members[member] {
			return errors.New("同一用户在同一入站只能有一条凭据")
		}
		members[member] = true
		counts[cr.InboundID]++
		if counts[cr.InboundID] > 512 {
			return errors.New("单个入站最多 512 条用户凭据，请拆分入站")
		}
	}
	if strings.TrimSpace(c.Settings.Workspace) == "" || len([]rune(c.Settings.Workspace)) > 40 {
		return errors.New("工作空间名称无效")
	}
	return nil
}
func credentialLink(n *Inbound, cr *Credential) string {
	values := url.Values{"server": {n.PublicHost}, "port": {fmt.Sprint(n.Port)}, "secret": {"ee" + cr.Secret + hex.EncodeToString([]byte(n.TLSDomain))}}
	return "tg://proxy?" + values.Encode()
}
