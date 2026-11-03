package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errRevisionConflict = errors.New("配置已被其他会话修改，请刷新后重试")

func checkRevision(r *http.Request, c *Config) error {
	value := r.Header.Get("If-Match")
	if value == "" {
		return nil
	}
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision != c.Revision {
		return errRevisionConflict
	}
	return nil
}
func failChange(w http.ResponseWriter, err error) {
	code := 400
	if errors.Is(err, errRevisionConflict) {
		code = 409
	}
	fail(w, code, err.Error())
}

type loginSession struct {
	Expires   time.Time
	AdminHash [32]byte
}
type loginAttempt struct {
	Count     int
	Until     time.Time
	AdminHash [32]byte
}
type API struct {
	s              *Service
	mu             sync.Mutex
	sessions       map[[32]byte]loginSession
	attempts       map[string]loginAttempt
	adminHost      string
	secureCookie   bool
	updater        *panelUpdater
	entryDefaults  *inboundDefaults
	trustedProxies []netip.Prefix
	loginSlots     chan struct{}
}

func newAPI(s *Service, host string, secure bool) *API {
	return &API{s: s, sessions: map[[32]byte]loginSession{}, attempts: map[string]loginAttempt{}, adminHost: host, secureCookie: secure, updater: newPanelUpdater("", false), loginSlots: make(chan struct{}, 4)}
}

func (a *API) loginPeer(r *http.Request) (string, error) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("无法识别登录来源")
	}
	ip := peer.Addr().Unmap()
	trusted := func(ip netip.Addr) bool {
		for _, prefix := range a.trustedProxies {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !trusted(ip) {
		return ip.String(), nil
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		forwarded = r.Header.Get("X-Real-IP")
	}
	chain := strings.Split(forwarded, ",")
	if forwarded == "" || len(forwarded) > 1024 || len(chain) > 16 {
		return "", errors.New("可信反向代理必须正确传递 X-Forwarded-For 或 X-Real-IP")
	}
	for i := len(chain) - 1; i >= 0; i-- {
		ip, err = netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil || ip.Zone() != "" {
			return "", errors.New("反向代理来源地址无效")
		}
		ip = ip.Unmap()
		if !trusted(ip) {
			return ip.String(), nil
		}
	}
	return ip.String(), nil
}
func sendJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	sendJSON(w, status, map[string]string{"error": message})
}
func readJSON(r *http.Request, dst any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("请使用 application/json 请求")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 524289))
	if err != nil {
		return err
	}
	if len(body) > 524288 {
		return errors.New("请求内容过大")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(dst); err != nil {
		return errors.New("请求字段或 JSON 格式无效")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("请求包含多余内容")
	}
	return nil
}
func loopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !loopbackHost(r.Host) && !(a.adminHost != "" && strings.EqualFold(host, a.adminHost)) {
		fail(w, 403, "管理地址未获允许")
		return
	}
	if r.Method != http.MethodGet {
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(u.Host, r.Host) || (u.Scheme != "http" && u.Scheme != "https") {
				fail(w, 403, "不允许跨站管理请求")
				return
			}
		}
	}
	switch r.URL.Path {
	case "/api/auth":
		if r.Method != http.MethodGet {
			fail(w, 405, "请求方式不支持")
			return
		}
		progress := a.updater.progress()
		sendJSON(w, 200, map[string]any{"initialized": a.s.store.hasAdmin(), "authenticated": a.authenticated(r), "version": buildVersion, "ready": a.s.engine.ready(), "updatePhase": progress.Phase, "updateTarget": progress.Target})
		return
	case "/api/setup":
		a.setup(w, r)
		return
	case "/api/login":
		a.login(w, r)
		return
	}
	if !a.authenticated(r) {
		fail(w, 401, "请先登录管理面板")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/update") {
		a.serveUpdate(w, r)
		return
	}
	if r.URL.Path == "/api/logout" {
		if r.Method != http.MethodPost {
			fail(w, 405, "请求方式不支持")
			return
		}
		if cookie, err := r.Cookie("tg_session"); err == nil {
			key := sha256.Sum256([]byte(cookie.Value))
			a.mu.Lock()
			delete(a.sessions, key)
			a.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "tg_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.secureCookie})
		sendJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if r.URL.Path == "/api/state" && r.Method == http.MethodGet {
		a.state(w)
		return
	}
	if r.URL.Path == "/api/inbound-defaults" && r.Method == http.MethodGet {
		if a.entryDefaults == nil {
			fail(w, 503, "自动识别暂不可用，请手动填写服务器公网地址")
			return
		}
		host, source, err := a.entryDefaults.detect(r.Context(), a.s.config.Load(), a.adminHost)
		if err != nil {
			fail(w, 503, err.Error())
			return
		}
		sendJSON(w, 200, map[string]string{"host": host, "source": source})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	if len(parts) == 3 && parts[0] == "outbounds" && parts[2] == "test" && r.Method == http.MethodPost {
		h, err := a.s.probe(parts[1])
		if err != nil {
			failChange(w, err)
		} else {
			sendJSON(w, 200, h)
		}
		return
	}
	if len(parts) == 3 && parts[0] == "inbounds" && parts[2] == "test" && r.Method == http.MethodPost {
		checks, err := a.s.probeInbound(parts[1])
		if err != nil {
			failChange(w, err)
		} else {
			sendJSON(w, 200, checks)
		}
		return
	}
	if len(parts) == 3 && parts[0] == "credentials" && parts[2] == "link" && r.Method == http.MethodGet {
		cfg := a.s.config.Load()
		cr := cfg.credential(parts[1])
		if cr == nil {
			fail(w, 404, "凭据不存在")
			return
		}
		n := cfg.inbound(cr.InboundID)
		warnings := []string{}
		if !n.Enabled {
			warnings = append(warnings, "入站已停用")
		}
		if !a.s.allowed(cr.UserID, cr.ID, cr.InboundID) {
			warnings = append(warnings, "用户或凭据已停用、到期，或流量额度已耗尽")
		}
		if _, _, err := cfg.resolve(n.ID); err != nil {
			warnings = append(warnings, err.Error()+"；请在路由管理中选择直连或落地")
		}
		if ip := net.ParseIP(n.PublicHost); n.PublicHost == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())) {
			warnings = append(warnings, "公开入口使用本地或内网地址，公网用户可能无法访问")
		}
		values := strings.TrimPrefix(credentialLink(n, cr), "tg://proxy?")
		sendJSON(w, 200, map[string]any{"link": "tg://proxy?" + values, "webLink": "https://t.me/proxy?" + values, "warnings": warnings})
		return
	}
	if len(parts) == 3 && parts[0] == "users" && parts[2] == "assign" && r.Method == http.MethodPost {
		var input struct {
			InboundIDs []string `json:"inboundIDs"`
		}
		if err := readJSON(r, &input); err != nil {
			failChange(w, err)
			return
		}
		err := a.s.update(func(c *Config) error {
			if err := checkRevision(r, c); err != nil {
				return err
			}

			if c.user(parts[1]) == nil {
				return errors.New("用户不存在")
			}
			selected := map[string]bool{}
			for _, id := range input.InboundIDs {
				if c.inbound(id) == nil {
					return errors.New("入站不存在")
				}
				selected[id] = true
			}
			c.Credentials = slices.DeleteFunc(c.Credentials, func(cr Credential) bool { return cr.UserID == parts[1] && !selected[cr.InboundID] })
			for id := range selected {
				exists := false
				for _, cr := range c.Credentials {
					if cr.UserID == parts[1] && cr.InboundID == id {
						exists = true
						break
					}
				}
				if !exists {
					c.Credentials = append(c.Credentials, Credential{ID: newID(), InboundID: id, UserID: parts[1], Secret: newSecret(), Enabled: true})
				}
			}
			return nil
		}, false)
		if err != nil {
			failChange(w, err)
			return
		}
		a.s.addEvent("info", "用户入站权限", "已更新用户的入站分配")
		sendJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if len(parts) == 1 && parts[0] == "settings" && r.Method == http.MethodPatch {
		current := a.s.config.Load().Settings
		settings := Settings{Workspace: current.Workspace, TLSDomains: append([]string(nil), current.TLSDomains...)}
		if err := readJSON(r, &settings); err != nil {
			failChange(w, err)
			return
		}
		if err := a.s.update(func(c *Config) error {
			if err := checkRevision(r, c); err != nil {
				return err
			}
			c.Settings = settings
			return nil
		}, false); err != nil {
			failChange(w, err)
			return
		}
		a.s.addEvent("info", "面板设置", "工作空间名称已更新")
		sendJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if len(parts) == 1 && parts[0] == "backup" && r.Method == http.MethodGet {
		a.s.updateMu.Lock()
		data := map[string]any{"version": 1, "config": cloneConfig(a.s.config.Load()), "usage": a.s.usageSnapshot()}
		a.s.updateMu.Unlock()
		w.Header().Set("Content-Disposition", `attachment; filename="tg-relay-backup.json"`)
		sendJSON(w, 200, data)
		return
	}
	if len(parts) >= 1 && len(parts) <= 2 {
		kind := parts[0]
		if kind == "inbounds" || kind == "outbounds" || kind == "routes" || kind == "users" || kind == "credentials" {
			id := ""
			if len(parts) == 2 {
				id = parts[1]
			}
			a.entity(w, r, kind, id)
			return
		}
	}
	fail(w, 404, "接口不存在")
}
func (a *API) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie("tg_session")
	if err != nil {
		return false
	}
	key := sha256.Sum256([]byte(cookie.Value))
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[key]
	if ok && time.Now().Before(session.Expires) {
		var hash []byte
		if err := a.s.store.db.QueryRow("SELECT hash FROM admin WHERE id=1").Scan(&hash); err == nil && session.AdminHash == sha256.Sum256(hash) {
			return true
		}
	}
	delete(a.sessions, key)
	return false
}
func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "请求方式不支持")
		return
	}
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(peer); ip == nil || !ip.IsLoopback() || !loopbackHost(r.Host) {
		fail(w, 403, "首次创建管理员必须从服务器本机访问")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &input); err != nil {
		failChange(w, err)
		return
	}
	adminHash, err := a.s.store.saveAdmin(input.Username, input.Password, false)
	if err != nil {
		code := 400
		if errors.Is(err, errAdminExists) {
			code = 409
		}
		fail(w, code, err.Error())
		return
	}
	a.s.addEvent("info", "初始化完成", "管理员账户已创建")
	a.issueSession(w, r, adminHash)
	sendJSON(w, 200, map[string]bool{"ok": true})
}
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, "请求方式不支持")
		return
	}
	peer, err := a.loginPeer(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &input); err != nil || len(input.Password) > 256 {
		fail(w, 400, "登录信息无效")
		return
	}
	select {
	case a.loginSlots <- struct{}{}:
		defer func() { <-a.loginSlots }()
	default:
		fail(w, 429, "登录繁忙，请稍后重试")
		return
	}
	var currentHash []byte
	if err := a.s.store.db.QueryRow("SELECT hash FROM admin WHERE id=1").Scan(&currentHash); err != nil {
		if err == sql.ErrNoRows {
			fail(w, 409, "请先创建管理员")
		} else {
			fail(w, 500, "登录服务不可用")
		}
		return
	}
	credentialRevision := sha256.Sum256(currentHash)
	a.mu.Lock()
	now := time.Now()
	attempt, exists := a.attempts[peer]
	if now.After(attempt.Until) || attempt.AdminHash != credentialRevision {
		attempt = loginAttempt{Until: now.Add(10 * time.Minute), AdminHash: credentialRevision}
	}
	if attempt.Count >= 10 {
		a.mu.Unlock()
		fail(w, 429, "登录尝试过多，请稍后再试")
		return
	}
	if !exists && len(a.attempts) >= 1024 {
		for key, v := range a.attempts {
			if now.After(v.Until) {
				delete(a.attempts, key)
			}
		}
		if len(a.attempts) >= 1024 {
			a.mu.Unlock()
			fail(w, 429, "登录繁忙，请稍后再试")
			return
		}
	}
	attempt.Count++
	a.attempts[peer] = attempt
	a.mu.Unlock()
	adminHash, err := a.s.store.authenticateAdmin(input.Username, input.Password)
	if err == sql.ErrNoRows {
		fail(w, 409, "请先创建管理员")
		return
	}
	if errors.Is(err, errAdminCredentials) {
		fail(w, 401, err.Error())
		return
	}
	if err != nil {
		fail(w, 500, "登录服务不可用")
		return
	}
	a.mu.Lock()
	delete(a.attempts, peer)
	a.mu.Unlock()
	a.issueSession(w, r, adminHash)
	sendJSON(w, 200, map[string]bool{"ok": true})
}
func (a *API) issueSession(w http.ResponseWriter, r *http.Request, adminHash [32]byte) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	key := sha256.Sum256([]byte(token))
	expires := time.Now().Add(12 * time.Hour)
	a.mu.Lock()
	for k, v := range a.sessions {
		if time.Now().After(v.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 64 {
		for k := range a.sessions {
			delete(a.sessions, k)
			break
		}
	}
	a.sessions[key] = loginSession{Expires: expires, AdminHash: adminHash}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "tg_session", Value: token, Path: "/", HttpOnly: true, Secure: a.secureCookie || r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: 43200})
}
func (a *API) state(w http.ResponseWriter) {
	a.s.updateMu.Lock()
	public := cloneConfig(a.s.config.Load())
	for i := range public.Outbounds {
		public.Outbounds[i].HasPassword = public.Outbounds[i].Password != ""
		public.Outbounds[i].Password = ""
	}
	for i := range public.Credentials {
		public.Credentials[i].Secret = ""
	}
	a.s.healthMu.Lock()
	health := map[string]Health{}
	for id, h := range a.s.health {
		health[id] = h
	}
	a.s.healthMu.Unlock()
	a.s.eventMu.Lock()
	events := append([]Event(nil), a.s.events...)
	a.s.eventMu.Unlock()
	a.s.usageMu.Lock()
	up, down, persistErr := a.s.rateUp, a.s.rateDown, a.s.persistError
	a.s.usageMu.Unlock()
	result := map[string]any{"version": buildVersion, "config": public, "usage": a.s.usageSnapshot(), "nodes": a.s.engine.snapshot(), "health": health, "events": events, "uploadRate": up, "downloadRate": down, "persistenceError": persistErr, "uptimeSeconds": int64(time.Since(a.s.started).Seconds())}
	a.s.updateMu.Unlock()
	sendJSON(w, 200, result)
}
func entityIndex[T any](items []T, id string, getID func(T) string) int {
	return slices.IndexFunc(items, func(v T) bool { return getID(v) == id })
}
func saveEntity[T any](items *[]T, index int, value T, remove bool) {
	if remove {
		*items = append((*items)[:index], (*items)[index+1:]...)
	} else if index < 0 {
		*items = append(*items, value)
	} else {
		(*items)[index] = value
	}
}
func (a *API) entity(w http.ResponseWriter, r *http.Request, kind, id string) {
	if !((r.Method == http.MethodPost && id == "") || ((r.Method == http.MethodPatch || r.Method == http.MethodDelete) && id != "")) {
		fail(w, 405, "请求方式不支持")
		return
	}
	var body json.RawMessage
	if r.Method != http.MethodDelete {
		if err := readJSON(r, &body); err != nil {
			failChange(w, err)
			return
		}
	}
	remove := r.Method == http.MethodDelete
	createdID := id
	if createdID == "" {
		createdID = newID()
	}
	entityName := ""
	err := a.s.update(func(c *Config) error {
		if err := checkRevision(r, c); err != nil {
			return err
		}

		decode := func(dst any) error {
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(dst); err != nil {
				return errors.New("配置字段无效")
			}
			return nil
		}
		switch kind {
		case "inbounds":
			index := entityIndex(c.Inbounds, id, func(v Inbound) string { return v.ID })
			if id != "" && index < 0 {
				return errors.New("入站不存在")
			}
			v := Inbound{ListenIP: "0.0.0.0", Enabled: true}
			if index >= 0 {
				v = c.Inbounds[index]
			}
			var input struct {
				Inbound
				InitialRoute *struct {
					Direct     bool   `json:"direct"`
					OutboundID string `json:"outboundID"`
				} `json:"initialRoute"`
			}
			input.Inbound = v
			if !remove {
				if err := decode(&input); err != nil {
					return err
				}
				v = input.Inbound
				if input.InitialRoute != nil {
					if id != "" {
						return errors.New("已有入站请通过路由管理修改转发方式")
					}
					c.Routes = append(c.Routes, Route{ID: newID(), Name: v.Name, InboundIDs: []string{createdID}, Direct: input.InitialRoute.Direct, OutboundID: input.InitialRoute.OutboundID, Priority: 100, Enabled: true})
				}
			}
			v.ID = createdID
			entityName = v.Name
			saveEntity(&c.Inbounds, index, v, remove)
			if remove {
				c.Credentials = slices.DeleteFunc(c.Credentials, func(cr Credential) bool { return cr.InboundID == id })
				for i := range c.Routes {
					c.Routes[i].InboundIDs = slices.DeleteFunc(c.Routes[i].InboundIDs, func(nid string) bool { return nid == id })
				}
				c.Routes = slices.DeleteFunc(c.Routes, func(route Route) bool { return len(route.InboundIDs) == 0 })
			}
		case "outbounds":
			index := entityIndex(c.Outbounds, id, func(v Outbound) string { return v.ID })
			if id != "" && index < 0 {
				return errors.New("出口不存在")
			}
			v := Outbound{Type: "SOCKS5", Enabled: true}
			if index >= 0 {
				v = c.Outbounds[index]
			}
			if !remove {
				if err := decode(&v); err != nil {
					return err
				}
			} else {
				for _, route := range c.Routes {
					if route.OutboundID == id {
						return errors.New("请先删除或修改引用此出口的路由")
					}
				}
			}
			v.ID = createdID
			v.HasPassword = false
			entityName = v.Name
			saveEntity(&c.Outbounds, index, v, remove)
		case "routes":
			index := entityIndex(c.Routes, id, func(v Route) string { return v.ID })
			if id != "" && index < 0 {
				return errors.New("路由不存在")
			}
			v := Route{Enabled: true, Priority: 100}
			if index >= 0 {
				v = c.Routes[index]
			}
			if !remove {
				if err := decode(&v); err != nil {
					return err
				}
			}
			v.ID = createdID
			entityName = v.Name
			saveEntity(&c.Routes, index, v, remove)
		case "users":
			index := entityIndex(c.Users, id, func(v User) string { return v.ID })
			if id != "" && index < 0 {
				return errors.New("用户不存在")
			}
			v := User{Enabled: true}
			if index >= 0 {
				v = c.Users[index]
			}
			if !remove {
				if err := decode(&v); err != nil {
					return err
				}
			}
			v.ID = createdID
			entityName = v.Name
			saveEntity(&c.Users, index, v, remove)
			if remove {
				c.Credentials = slices.DeleteFunc(c.Credentials, func(cr Credential) bool { return cr.UserID == id })
			}
		case "credentials":
			index := entityIndex(c.Credentials, id, func(v Credential) string { return v.ID })
			if id != "" && index < 0 {
				return errors.New("凭据不存在")
			}
			v := Credential{Enabled: true, Secret: newSecret()}
			if index >= 0 {
				v = c.Credentials[index]
			}
			var input struct {
				InboundID string `json:"inboundID"`
				UserID    string `json:"userID"`
				Enabled   bool   `json:"enabled"`
			}
			input.InboundID = v.InboundID
			input.UserID = v.UserID
			input.Enabled = v.Enabled
			if !remove {
				if err := decode(&input); err != nil {
					return err
				}
			}
			v.ID = createdID
			v.InboundID = input.InboundID
			v.UserID = input.UserID
			v.Enabled = input.Enabled
			entityName = "用户凭据"
			saveEntity(&c.Credentials, index, v, remove)
		}
		return nil
	}, r.URL.Query().Get("mode") == "immediate" || remove)
	if err != nil {
		failChange(w, err)
		return
	}
	verb := map[string]string{http.MethodPost: "已创建", http.MethodPatch: "已更新", http.MethodDelete: "已删除"}[r.Method]
	a.s.addEvent("info", entityName, verb+"配置 · "+kind)
	sendJSON(w, 200, map[string]any{"ok": true, "id": createdID})
}
