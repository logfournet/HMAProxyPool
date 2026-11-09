package main

// Supervisor keeps one tunnel alive against HMA's WireGuard backend without
// the HMA client. It owns the session lifecycle:
//
//	mint -> build members for all peers of all sessions -> probe ->
//	  on failure: retry / re-mint (session TTL ~240s)
//
// HMA binds each minted session to exactly one of its 4 peers at a time (chosen
// server-side and roving), and periodically blackholes a whole session for a
// few seconds. We therefore (a) keep every peer of a session as a hedged
// member, and (b) optionally keep several independent sessions per tunnel so a
// dead window on one server does not stall the proxy.

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type MintConfig struct {
	JWT           string
	// Token, when set, is consulted on every mint so a rotated access token
	// takes effect without restarting anything.
	Token         func() string
	ServerIP      string // pin to one server; empty = auto/rotate
	LocationKey   string // country/city key (e.g. "US" or "US-OR-PORTLAND"); empty = default
	ProbeURL      string // full HTTPS URL fetched through the tunnel as a health check
	ProbeInterval time.Duration
	ProbeTimeout  time.Duration
	FailLimit     int
	RemintMargin  time.Duration // re-mint when age > ttl - margin
	MaxAttempts   int
	Sessions      int // independent sessions per tunnel (1..N)
}

// accessToken returns the token to mint with right now.
func (c *MintConfig) accessToken() string {
	if c.Token != nil {
		if t := c.Token(); t != "" {
			return t
		}
	}
	return c.JWT
}

func (c *MintConfig) defaults() {
	if c.ProbeURL == "" {
		c.ProbeURL = "https://icanhazip.com/"
	}
	if c.ProbeInterval <= 0 {
		c.ProbeInterval = 10 * time.Second
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = 8 * time.Second
	}
	if c.FailLimit <= 0 {
		c.FailLimit = 3
	}
	if c.RemintMargin <= 0 {
		c.RemintMargin = 40 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 8
	}
	if c.Sessions <= 0 {
		c.Sessions = 1
	}
}

type Supervisor struct {
	t    *Tunnel
	base TunnelConfig // name/port/http_port/mtu fixed per tunnel
	mcfg MintConfig

	mu       sync.Mutex
	sessions []*MintedSession
	peerIdx  int
	lastErr  string
	remints  int64
	peerSwap int64
	up       bool

	stop  chan struct{}
	done  chan struct{}
	renew chan struct{}
}

func NewSupervisor(t *Tunnel, base TunnelConfig, mcfg MintConfig) *Supervisor {
	mcfg.defaults()
	s := &Supervisor{t: t, base: base, mcfg: mcfg, stop: make(chan struct{}), done: make(chan struct{}), renew: make(chan struct{}, 1)}
	t.Sup = s
	return s
}

// requestRenew asks the supervisor for fresh sessions without blocking the
// caller. Safe to call from any goroutine; extra requests collapse into one.
func (s *Supervisor) requestRenew() {
	select {
	case s.renew <- struct{}{}:
	default:
	}
}

func (s *Supervisor) Start() { go s.run() }

func (s *Supervisor) Stop() {
	close(s.stop)
	<-s.done
}

func (s *Supervisor) run() {
	defer close(s.done)
	s.ensureConnected()
	ticker := time.NewTicker(s.mcfg.ProbeInterval)
	defer ticker.Stop()
	fails := 0
	for {
		select {
		case <-s.stop:
			return
		case <-s.renew:
			log.Printf("[%s] renew requested by dialer", s.t.Name)
			s.ensureConnected()
			fails = 0
			continue
		case <-ticker.C:
		}

		s.mu.Lock()
		sess := s.sessions
		s.mu.Unlock()
		due := false
		ttl := defaultTTL
		if len(sess) > 0 {
			ttl = sess[0].TTL
			due = sess[0].age() >= time.Duration(ttl)*time.Second-s.mcfg.RemintMargin
		}
		if due {
			log.Printf("[%s] session near TTL (%ds), re-minting", s.t.Name, ttl)
			s.ensureConnected()
			fails = 0
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), s.mcfg.ProbeTimeout)
		ip, err := s.t.GetExitIP(ctx, s.mcfg.ProbeURL)
		cancel()
		if err != nil {
			fails++
			log.Printf("[%s] probe fail %d/%d: %v", s.t.Name, fails, s.mcfg.FailLimit, err)
			if fails >= s.mcfg.FailLimit {
				log.Printf("[%s] path dead, re-establishing", s.t.Name)
				s.ensureConnected()
				fails = 0
			}
		} else {
			if fails > 0 {
				log.Printf("[%s] probe ok, exit %s", s.t.Name, ip)
			}
			fails = 0
		}
	}
}

// ensureConnected mints fresh sessions and brings the tunnel onto all their peers.
func (s *Supervisor) ensureConnected() {
	var lastErr string
	for attempt := 0; attempt < s.mcfg.MaxAttempts; attempt++ {
		minted, err := s.mintAll()
		if err != nil {
			lastErr = err.Error()
			s.setErr(lastErr)
			time.Sleep(2 * time.Second)
			continue
		}
		if s.trySessions(minted) {
			return
		}
		lastErr = "sessions have no live path"
		time.Sleep(1500 * time.Millisecond)
	}
	s.setErr("could not establish a session after retries: " + lastErr)
}

// mintAll mints one or more sessions, preferring distinct servers.
func (s *Supervisor) mintAll() ([]*MintedSession, error) {
	jwt := s.mcfg.accessToken()
	// A location key pins discovery to that country/city, so the wrangler we
	// mint against (and therefore the exit IP) is in the requested country.
	servers, err := DiscoveryIn(jwt, s.mcfg.LocationKey)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if s.mcfg.ServerIP != "" {
		var pinned []HMAServer
		for _, x := range servers {
			if x.IP == s.mcfg.ServerIP {
				pinned = append(pinned, x)
			}
		}
		if len(pinned) == 0 {
			return nil, fmt.Errorf("server %s not in discovery", s.mcfg.ServerIP)
		}
		servers = pinned
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers for location %q", s.mcfg.LocationKey)
	}
	rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })

	n := s.mcfg.Sessions
	out := make([]*MintedSession, 0, n)
	for i := 0; i < n; i++ {
		srv := servers[i%len(servers)]
		m, err := MintSession(srv, jwt, s.mcfg.ProbeTimeout)
		if err != nil {
			if len(out) > 0 {
				continue // keep what we have
			}
			return nil, fmt.Errorf("mint %s: %w", srv.IP, err)
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no sessions minted")
	}
	return out, nil
}

// trySessions builds a member for every peer of every session and probes.
func (s *Supervisor) trySessions(minted []*MintedSession) bool {
	cfgs := make([]TunnelConfig, 0, len(minted)*4)
	for _, m := range minted {
		for _, p := range m.Peers {
			cfgs = append(cfgs, s.cfgFor(m, p))
		}
	}
	if err := s.t.ReplaceMany(cfgs); err != nil {
		s.setErr("replace: " + err.Error())
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.mcfg.ProbeTimeout)
	ip, err := s.t.GetExitIP(ctx, s.mcfg.ProbeURL)
	cancel()
	if err != nil {
		s.setErr(fmt.Sprintf("no live path across %d sessions: %v", len(minted), err))
		atomic.AddInt64(&s.peerSwap, 1)
		return false
	}
	s.mu.Lock()
	if len(s.sessions) > 0 {
		atomic.AddInt64(&s.remints, 1)
	}
	s.sessions = minted
	s.peerIdx = 0
	s.lastErr = ""
	s.up = true
	s.mu.Unlock()

	ctips := make([]string, 0, len(minted))
	for _, m := range minted {
		ctips = append(ctips, m.Ctip)
	}
	log.Printf("[%s] live exit=%s sessions=%v members=%d", s.t.Name, ip, ctips, len(cfgs))
	return true
}

func (s *Supervisor) cfgFor(m *MintedSession, peer PeerConfig) TunnelConfig {
	cfg := s.base
	cfg.PrivateKey = hex.EncodeToString(m.PrivKey)
	cfg.Addresses = []string{m.Ctip}
	cfg.DNS = []string{m.CDNS}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	cfg.Peer = peer
	return cfg
}

func (s *Supervisor) setErr(e string) {
	s.mu.Lock()
	s.lastErr = e
	s.mu.Unlock()
	log.Printf("[%s] %s", s.t.Name, e)
}

func (s *Supervisor) currentSession() *MintedSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) == 0 {
		return nil
	}
	return s.sessions[0]
}

func (s *Supervisor) status() (peerIdx int, sessionAge time.Duration, remints, swaps int64, lastErr string, up bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) > 0 {
		sessionAge = s.sessions[0].age()
	}
	return s.peerIdx, sessionAge, s.remints, s.peerSwap, s.lastErr, s.up
}
