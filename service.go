package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Service struct {
	store        *Store
	config       atomic.Pointer[Config]
	updateMu     sync.Mutex
	usageMu      sync.Mutex
	usage        map[string]Usage
	reserved     map[string]int64
	eventMu      sync.Mutex
	events       []Event
	healthMu     sync.Mutex
	health       map[string]Health
	engine       *Engine
	started      time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	rateUp       int64
	rateDown     int64
	persistError string
}

func newService(store *Store) (*Service, error) {
	c, usage, events, err := store.load()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{store: store, usage: usage, reserved: map[string]int64{}, events: events, health: map[string]Health{}, started: time.Now(), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	s.config.Store(c)
	s.engine = newEngine(s)
	plan, err := s.engine.prepare(c)
	if err != nil {
		s.addEvent("error", "入站启动失败", err.Error())
	} else {
		s.engine.apply(plan, c, false)
	}
	go s.background()
	return s, nil
}
func (s *Service) addEvent(level, title, detail string) {
	e := Event{Time: time.Now().UTC(), Level: level, Title: title, Detail: detail}
	s.eventMu.Lock()
	s.events = append([]Event{e}, s.events...)
	if len(s.events) > 200 {
		s.events = s.events[:200]
	}
	s.eventMu.Unlock()
	if err := s.store.event(e); err != nil {
		log.Printf("event persistence: %v", err)
	}
}
func (s *Service) update(change func(*Config) error, immediate bool) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	next := cloneConfig(s.config.Load())
	if err := change(next); err != nil {
		return err
	}
	if err := validateConfig(next); err != nil {
		return err
	}
	plan, err := s.engine.prepare(next)
	if err != nil {
		return err
	}
	next.Revision++
	if err = s.store.saveConfig(next); err != nil {
		plan.abort()
		return err
	}
	s.config.Store(next)
	s.engine.apply(plan, next, immediate)
	return nil
}
func (s *Service) allowed(userID, credentialID, inboundID string) bool {
	c := s.config.Load()
	u := c.user(userID)
	cr := c.credential(credentialID)
	n := c.inbound(inboundID)
	if u == nil || !u.Enabled || cr == nil || !cr.Enabled || n == nil || !n.Enabled || cr.UserID != userID || cr.InboundID != inboundID {
		return false
	}
	if u.Expires != "" {
		expires, _ := time.Parse(time.RFC3339, u.Expires)
		if !time.Now().Before(expires) {
			return false
		}
	}
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	return u.QuotaBytes == 0 || s.usage["user:"+userID].Total() < u.QuotaBytes
}
func (s *Service) reserve(userID string, want int) int {
	u := s.config.Load().user(userID)
	if u == nil || !u.Enabled {
		return 0
	}
	if u.Expires != "" {
		expires, _ := time.Parse(time.RFC3339, u.Expires)
		if !time.Now().Before(expires) {
			return 0
		}
	}
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	n := int64(want)
	if u.QuotaBytes > 0 {
		remaining := u.QuotaBytes - s.usage["user:"+userID].Total() - s.reserved[userID]
		if remaining <= 0 {
			return 0
		}
		if n > remaining {
			n = remaining
		}
	}
	s.reserved[userID] += n
	return int(n)
}
func (s *Service) settle(session *Session, reserved, actual int, upload bool) {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	s.reserved[session.UserID] -= int64(reserved)
	for _, key := range []string{"user:" + session.UserID, "inbound:" + session.InboundID, "outbound:" + session.OutboundID, "total:all"} {
		u := s.usage[key]
		if upload {
			u.Upload += int64(actual)
		} else {
			u.Download += int64(actual)
		}
		s.usage[key] = u
	}
}
func (s *Service) usageSnapshot() map[string]Usage {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	dst := make(map[string]Usage, len(s.usage))
	for k, v := range s.usage {
		dst[k] = v
	}
	return dst
}
func (s *Service) flush() error {
	err := s.store.saveUsage(s.usageSnapshot())
	s.usageMu.Lock()
	if err != nil {
		s.persistError = err.Error()
	} else {
		s.persistError = ""
	}
	s.usageMu.Unlock()
	return err
}
func (s *Service) background() {
	defer close(s.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	flushTick := time.NewTicker(2 * time.Second)
	defer flushTick.Stop()
	last := s.usageSnapshot()["total:all"]
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
			s.engine.closeUnauthorized()
			now := s.usageSnapshot()["total:all"]
			s.usageMu.Lock()
			s.rateUp = now.Upload - last.Upload
			s.rateDown = now.Download - last.Download
			s.usageMu.Unlock()
			last = now
		case <-flushTick.C:
			if err := s.flush(); err != nil {
				log.Printf("usage persistence: %v", err)
			}
		}
	}
}
func (s *Service) close() error { s.cancel(); s.engine.close(); <-s.done; return s.flush() }
func (s *Service) probe(id string) (Health, error) {
	o := s.config.Load().outbound(id)
	if o == nil {
		return Health{}, errors.New("出口不存在")
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	started := time.Now()
	conn, err := dialOutbound(ctx, *o, "149.154.167.51:443")
	h := Health{Healthy: err == nil, LatencyMS: time.Since(started).Milliseconds(), TestedAt: time.Now().UTC()}
	if conn != nil {
		conn.Close()
	}
	if err != nil {
		h.Error = err.Error()
	}
	s.healthMu.Lock()
	s.health[id] = h
	s.healthMu.Unlock()
	s.addEvent(map[bool]string{true: "info", false: "warn"}[h.Healthy], o.Name, "TCP 隧道连接测试"+map[bool]string{true: "成功", false: "失败"}[h.Healthy])
	return h, nil
}

// Tests the configured server-side path, not public reachability or a Telegram client session.
func (s *Service) probeInbound(id string) ([]Health, error) {
	c := s.config.Load()
	n := c.inbound(id)
	if n == nil || !n.Enabled {
		return nil, errors.New("入站不存在或已停用")
	}
	_, o, err := c.resolve(id)
	if err != nil {
		return nil, err
	}
	checks := make([]Health, 0, 2)
	for _, target := range []string{dcAddresses(2)[0], net.JoinHostPort(n.TLSDomain, "443")} {
		ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
		started := time.Now()
		conn, err := dialOutbound(ctx, *o, target)
		h := Health{Healthy: err == nil, LatencyMS: time.Since(started).Milliseconds(), TestedAt: time.Now().UTC()}
		if conn != nil {
			conn.Close()
		}
		cancel()
		if err != nil {
			h.Error = err.Error()
		}
		checks = append(checks, h)
	}
	return checks, nil
}
