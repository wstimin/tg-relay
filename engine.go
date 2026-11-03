package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"tgrelay/internal/mtproto/fake"
	"tgrelay/internal/mtproto/obfuscation"
	tlsrecord "tgrelay/internal/mtproto/record"
)

type Session struct {
	InboundID, UserID, CredentialID, OutboundID, RouteID, Address, Fingerprint string
	client                                                                     net.Conn
	upstream                                                                   net.Conn
	mu                                                                         sync.Mutex
	closed                                                                     bool
}

func (s *Session) close() {
	s.mu.Lock()
	s.closed = true
	up := s.upstream
	s.mu.Unlock()
	s.client.Close()
	if up != nil {
		up.Close()
	}
}
func (s *Session) setUpstream(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		conn.Close()
		return false
	}
	s.upstream = conn
	return true
}

type listenerEntry struct {
	net.Listener
	address string
}
type Engine struct {
	s            *Service
	mu           sync.Mutex
	listeners    map[string]*listenerEntry
	sessions     map[*Session]bool
	handshakes   chan struct{}
	wg           sync.WaitGroup
	closing      bool
	replayMu     sync.Mutex
	replays      map[[32]byte]time.Time
	nextReplayGC time.Time
}
type listenerPlan struct {
	opened  map[string]*listenerEntry
	keep    map[string]*listenerEntry
	retired map[string]*listenerEntry
}

func (p *listenerPlan) abort() {
	for _, l := range p.opened {
		l.Close()
	}
}
func newEngine(s *Service) *Engine {
	return &Engine{s: s, listeners: map[string]*listenerEntry{}, sessions: map[*Session]bool{}, handshakes: make(chan struct{}, 64), replays: map[[32]byte]time.Time{}}
}
func inboundAddress(n *Inbound) string { return net.JoinHostPort(n.ListenIP, strconv.Itoa(n.Port)) }
func outboundFingerprint(o *Outbound) string {
	b, _ := json.Marshal(o)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (e *Engine) prepare(c *Config) (*listenerPlan, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return nil, errors.New("服务正在关闭")
	}
	p := &listenerPlan{opened: map[string]*listenerEntry{}, keep: map[string]*listenerEntry{}, retired: map[string]*listenerEntry{}}
	for _, n := range c.Inbounds {
		if !n.Enabled {
			continue
		}
		address := inboundAddress(&n)
		if old := e.listeners[n.ID]; old != nil && old.address == address {
			p.keep[n.ID] = old
			continue
		}
		l, err := net.Listen("tcp", address)
		if err != nil {
			p.abort()
			if errors.Is(err, syscall.EADDRINUSE) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10048))) {
				return nil, fmt.Errorf("端口 %d 已被占用，无法启动入站「%s」。请换一个空闲端口；面板与 TG 入站不能共用监听地址和端口: %w", n.Port, n.Name, err)
			}
			return nil, fmt.Errorf("无法监听入站 %s (%s): %w", n.Name, address, err)
		}
		p.opened[n.ID] = &listenerEntry{Listener: l, address: address}
	}
	for id, l := range e.listeners {
		if p.keep[id] == nil {
			p.retired[id] = l
		}
	}
	return p, nil
}
func (e *Engine) apply(p *listenerPlan, c *Config, immediate bool) {
	e.mu.Lock()
	for id, l := range p.retired {
		l.Close()
		delete(e.listeners, id)
	}
	for id, l := range p.opened {
		e.listeners[id] = l
		e.wg.Add(1)
		go e.accept(id, l)
	}
	toClose := []*Session{}
	for session := range e.sessions {
		n := c.inbound(session.InboundID)
		invalid := n == nil || !n.Enabled || inboundAddress(n) != session.Address
		if !invalid && session.UserID != "" {
			invalid = !e.s.allowed(session.UserID, session.CredentialID, session.InboundID)
		}
		if !invalid && immediate && session.UserID != "" {
			r, o, err := c.resolve(session.InboundID)
			invalid = err != nil || r.ID != session.RouteID || o.ID != session.OutboundID || outboundFingerprint(o) != session.Fingerprint
		}
		if invalid {
			toClose = append(toClose, session)
		}
	}
	e.mu.Unlock()
	for _, s := range toClose {
		s.close()
	}
}
func (e *Engine) accept(id string, l *listenerEntry) {
	defer e.wg.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
			_ = tcp.SetKeepAlive(true)
		}
		e.mu.Lock()
		if e.closing || len(e.sessions) >= 4096 {
			e.mu.Unlock()
			conn.Close()
			continue
		}
		session := &Session{InboundID: id, Address: l.address, client: conn}
		e.sessions[session] = true
		e.wg.Add(1)
		e.mu.Unlock()
		go func() {
			defer e.wg.Done()
			defer session.close()
			defer func() { e.mu.Lock(); delete(e.sessions, session); e.mu.Unlock() }()
			e.serve(session)
		}()
	}
}

type capturedConn struct {
	net.Conn
	data bytes.Buffer
}

func (c *capturedConn) Read(p []byte) (int, error) {
	if c.data.Len() >= 65536 {
		return 0, errors.New("握手过大")
	}
	if len(p) > 65536-c.data.Len() {
		p = p[:65536-c.data.Len()]
	}
	n, err := c.Conn.Read(p)
	c.data.Write(p[:n])
	return n, err
}
func (e *Engine) serve(session *Session) {
	select {
	case e.handshakes <- struct{}{}:
	default:
		return
	}
	handshakeHeld := true
	defer func() {
		if handshakeHeld {
			<-e.handshakes
		}
	}()
	cfg := e.s.config.Load()
	n := cfg.inbound(session.InboundID)
	if n == nil || !n.Enabled {
		return
	}
	_ = session.client.SetDeadline(time.Now().Add(8 * time.Second))
	keys := [][]byte{}
	credentials := []Credential{}
	for _, cr := range cfg.Credentials {
		if cr.InboundID != n.ID || !e.s.allowed(cr.UserID, cr.ID, n.ID) {
			continue
		}
		key, _ := hex.DecodeString(cr.Secret)
		keys = append(keys, key)
		credentials = append(credentials, cr)
	}
	captured := &capturedConn{Conn: session.client}
	hello, index, err := fake.ReadClientHello(captured, keys, n.TLSDomain, 5*time.Minute)
	if err != nil {
		e.mask(session, *n, captured.data.Bytes())
		return
	}
	if !e.replayAccept(hello.Random) {
		return
	}
	cr := credentials[index]
	if !e.s.allowed(cr.UserID, cr.ID, n.ID) {
		return
	}
	if err = fake.SendServerHello(session.client, keys[index], hello); err != nil {
		return
	}
	tlsConn := tlsrecord.New(session.client, true, true)
	dc, client, err := (obfuscation.Obfuscator{Secret: keys[index]}).ReadHandshake(tlsConn)
	if err != nil {
		return
	}
	// Resolve and publish the session together so an immediate route update cannot miss a handshake.
	e.mu.Lock()
	cfg = e.s.config.Load()
	r, o, err := cfg.resolve(n.ID)
	if err != nil {
		e.mu.Unlock()
		return
	}
	session.UserID = cr.UserID
	session.CredentialID = cr.ID
	session.OutboundID = o.ID
	session.RouteID = r.ID
	session.Fingerprint = outboundFingerprint(o)
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(e.s.ctx, 10*time.Second)
	var upstream net.Conn
	for _, address := range dcAddresses(dc) {
		upstream, err = dialOutbound(ctx, *o, address)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	cancel()
	if upstream == nil {
		return
	}
	if !session.setUpstream(upstream) {
		return
	}
	_ = upstream.SetDeadline(time.Now().Add(8 * time.Second))
	remote, err := (obfuscation.Obfuscator{}).SendHandshake(upstream, dc)
	if err != nil {
		return
	}
	if !e.s.allowed(cr.UserID, cr.ID, n.ID) {
		return
	}
	_ = upstream.SetDeadline(time.Time{})
	_ = session.client.SetDeadline(time.Time{})
	<-e.handshakes
	handshakeHeld = false
	done := make(chan struct{})
	go func() { e.transfer(session, remote, client, true); session.close(); close(done) }()
	e.transfer(session, client, remote, false)
	session.close()
	<-done
}
func (e *Engine) transfer(session *Session, dst, src net.Conn, upload bool) {
	buf := transferBuffers.Get().(*[16384]byte)
	defer transferBuffers.Put(buf)
	for {
		_ = src.SetReadDeadline(time.Now().Add(10 * time.Minute))
		n, readErr := src.Read(buf[:])
		if n > 0 {
			limit := e.s.reserve(session.UserID, n)
			if limit == 0 {
				return
			}
			_ = dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			written, err := dst.Write(buf[:limit])
			e.s.settle(session, limit, written, upload)
			if err != nil || written != limit || limit < n {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

var transferBuffers = sync.Pool{New: func() any { return new([16384]byte) }}

func (e *Engine) replayAccept(random [32]byte) bool {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	now := time.Now()
	if now.After(e.nextReplayGC) {
		for key, expires := range e.replays {
			if now.After(expires) {
				delete(e.replays, key)
			}
		}
		e.nextReplayGC = now.Add(30 * time.Second)
	}
	if _, ok := e.replays[random]; ok {
		return false
	}
	if len(e.replays) >= 65536 {
		return false
	}
	e.replays[random] = now.Add(12 * time.Minute)
	return true
}
func (e *Engine) mask(session *Session, n Inbound, prefix []byte) {
	// Only the administrator-configured SNI destination is reachable here, through the matched exit.
	_, o, err := e.s.config.Load().resolve(n.ID)
	if err != nil || len(prefix) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(e.s.ctx, 5*time.Second)
	defer cancel()
	remote, err := dialOutbound(ctx, *o, net.JoinHostPort(n.TLSDomain, "443"))
	if err != nil {
		return
	}
	defer remote.Close()
	if !session.setUpstream(remote) {
		return
	}
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	_ = session.client.SetDeadline(time.Now().Add(5 * time.Second))
	if writeAll(remote, prefix) != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.CopyN(remote, session.client, 128<<10); remote.Close(); close(done) }()
	_, _ = io.CopyN(session.client, remote, 128<<10)
	session.close()
	<-done
}
func (e *Engine) closeUnauthorized() {
	e.mu.Lock()
	closeList := []*Session{}
	for s := range e.sessions {
		if s.UserID != "" && !e.s.allowed(s.UserID, s.CredentialID, s.InboundID) {
			closeList = append(closeList, s)
		}
	}
	e.mu.Unlock()
	for _, s := range closeList {
		s.close()
	}
}
func (e *Engine) close() {
	e.mu.Lock()
	e.closing = true
	for _, l := range e.listeners {
		l.Close()
	}
	all := []*Session{}
	for s := range e.sessions {
		all = append(all, s)
	}
	e.mu.Unlock()
	for _, s := range all {
		s.close()
	}
	e.wg.Wait()
}
func (e *Engine) snapshot() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := map[string]any{}
	cfg := e.s.config.Load()
	for _, n := range cfg.Inbounds {
		count, old := 0, 0
		r, o, routeErr := cfg.resolve(n.ID)
		for s := range e.sessions {
			if s.InboundID == n.ID && s.UserID != "" {
				count++
				if routeErr != nil || s.RouteID != r.ID || s.OutboundID != o.ID || s.Fingerprint != outboundFingerprint(o) {
					old++
				}
			}
		}
		status := "running"
		message := ""
		if !n.Enabled {
			status = "paused"
		} else if e.listeners[n.ID] == nil {
			status = "offline"
			message = "入站监听未启动"
		} else if routeErr != nil {
			status = "warning"
			message = routeErr.Error()
		}
		routeID, outboundID := "", ""
		if r != nil {
			routeID = r.ID
		}
		if o != nil {
			outboundID = o.ID
		}
		state[n.ID] = map[string]any{"connections": count, "retiringConnections": old, "status": status, "error": message, "routeID": routeID, "outboundID": outboundID}
	}
	return state
}

func (e *Engine) ready() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, n := range e.s.config.Load().Inbounds {
		if n.Enabled && e.listeners[n.ID] == nil {
			return false
		}
	}
	return !e.closing
}

// Seed addresses follow Telegram Desktop / mtg. Negative identifiers retain media intent in the handshake.
func dcAddresses(dc int) []string {
	if dc < 0 {
		dc = -dc
	}
	switch dc {
	case 1:
		return []string{"149.154.175.50:443", "[2001:b28:f23d:f001::a]:443"}
	case 2:
		return []string{"149.154.167.51:443", "95.161.76.100:443", "[2001:67c:04e8:f002::a]:443"}
	case 3:
		return []string{"149.154.175.100:443", "[2001:b28:f23d:f003::a]:443"}
	case 4:
		return []string{"149.154.167.91:443", "[2001:67c:04e8:f004::a]:443"}
	case 5:
		return []string{"149.154.171.5:443", "[2001:b28:f23f:f005::a]:443"}
	case 203:
		return []string{"91.105.192.100:443", "[2a0a:f280:203:a:5000::100]:443"}
	}
	return nil
}
