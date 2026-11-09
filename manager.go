package main

// Manager owns the runtime set of keyed tunnels so they can be created,
// inspected, rotated and destroyed while the process is running.
//
// Nothing here is hardcoded per-account: a caller supplies an HMA token
// (the "key"), the manager validates it against discovery, mints sessions
// and hands back the resulting proxy endpoints.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Key is an HMA credential the manager can mint sessions with.
type Key struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	AddedAt   time.Time `json:"added_at"`
	Status    string    `json:"status"` // ok | invalid
	Note      string    `json:"note,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	mu    sync.RWMutex
	token string // never serialised
}

// Token returns the current access token.
func (k *Key) Token() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.token
}

// SetToken swaps in a fresh token and refreshes the expiry metadata.
// It reports whether the token actually changed.
func (k *Key) SetToken(token string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token == token {
		return false
	}
	k.token = token
	if exp, ok := jwtExpiry(token); ok {
		k.ExpiresAt = exp
	}
	k.Status = "ok"
	k.Note = describeToken(token)
	return true
}

// Proxy is one tunnel exposed as a pair of local proxy ports.
type Proxy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	KeyID     string    `json:"key_id"`
	Country   string    `json:"country,omitempty"` // requested ISO alpha-2 ("" = default)
	Socks5    string    `json:"socks5"`
	HTTP      string    `json:"http,omitempty"`
	Port      int       `json:"port"`
	HTTPPort  int       `json:"http_port,omitempty"`
	Sessions  int       `json:"sessions"`
	CreatedAt time.Time `json:"created_at"`

	t   *Tunnel
	sup *Supervisor
	ln  []net.Listener
}

// ProxyStatus is the live view of a Proxy.
type ProxyStatus struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	KeyID       string    `json:"key_id"`
	Country     string    `json:"country_requested,omitempty"` // ISO alpha-2 asked for at creation
	Socks5      string    `json:"socks5"`
	HTTP        string    `json:"http,omitempty"`
	Port        int       `json:"port"`
	HTTPPort    int       `json:"http_port,omitempty"`
	Sessions    int       `json:"sessions"`
	CreatedAt   time.Time `json:"created_at"`
	State       string    `json:"state"` // up | down | starting
	Up          bool      `json:"up"`
	ExitIP      string    `json:"exit_ip,omitempty"`
	SessionCtip string    `json:"session_ctip,omitempty"`
	SessionAge  int       `json:"session_age_sec,omitempty"`
	Remints     int64     `json:"remints,omitempty"`
	Hedges      int64     `json:"hedges,omitempty"`
	Dials       int64     `json:"dials,omitempty"`
	Errors      int64     `json:"errors,omitempty"`
	RxBytes     int64     `json:"rx_bytes"`
	TxBytes     int64     `json:"tx_bytes"`
	LastError   string    `json:"last_error,omitempty"`
}

type Manager struct {
	mu      sync.Mutex
	keys    map[string]*Key
	proxies map[string]*Proxy

	listenHost string
	portBase   int
	httpOffset int
	probeURL   string
	auth       ProxyAuth
	seq        int
}

func NewManager(listenHost string, portBase, httpOffset int, probeURL string) *Manager {
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	if portBase == 0 {
		portBase = 3000
	}
	if httpOffset == 0 {
		httpOffset = 1000
	}
	return &Manager{
		keys:       map[string]*Key{},
		proxies:    map[string]*Proxy{},
		listenHost: listenHost,
		portBase:   portBase,
		httpOffset: httpOffset,
		probeURL:   probeURL,
	}
}

func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------- keys

// AddKey validates the token against HMA discovery and stores it.
func (m *Manager) AddKey(name, token string) (*Key, error) {
	if token == "" {
		return nil, fmt.Errorf("empty key")
	}
	servers, err := Discovery(token)
	if err != nil {
		return nil, fmt.Errorf("key rejected by discovery: %w", err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("key accepted but discovery returned no servers")
	}
	k := &Key{
		ID:      newID(),
		Name:    name,
		AddedAt: time.Now(),
		Status:  "ok",
		Note:    fmt.Sprintf("%d wireguard servers visible", countWG(servers)),
	}
	k.SetToken(token)
	k.Note = fmt.Sprintf("%d wireguard servers visible; %s", countWG(servers), describeToken(token))
	m.mu.Lock()
	m.keys[k.ID] = k
	m.mu.Unlock()
	log.Printf("[api] key %s added (%s)", k.ID, k.Note)
	return k, nil
}

// SetAllTokens replaces the token on every registered key and reports how many
// changed. Used by the token-file feed, which is single-account by nature.
func (m *Manager) SetAllTokens(token string) int {
	m.mu.Lock()
	keys := make([]*Key, 0, len(m.keys))
	for _, k := range m.keys {
		keys = append(keys, k)
	}
	m.mu.Unlock()
	n := 0
	for _, k := range keys {
		if k.SetToken(token) {
			n++
		}
	}
	return n
}

// SetToken replaces the token of one key.
func (m *Manager) SetToken(id, token string) error {
	k := m.getKey(id)
	if k == nil {
		return fmt.Errorf("no such key")
	}
	if !k.SetToken(token) {
		return fmt.Errorf("token unchanged")
	}
	return nil
}

func countWG(servers []HMAServer) int {
	n := 0
	for _, s := range servers {
		if s.PubKey != "" {
			n++
		}
	}
	return n
}

func (m *Manager) getKey(id string) *Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[id]
}

func (m *Manager) ListKeys() []*Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Key, 0, len(m.keys))
	for _, k := range m.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AddedAt.Before(out[j].AddedAt) })
	return out
}

func (m *Manager) DeleteKey(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.proxies {
		if p.KeyID == id {
			return fmt.Errorf("key %s still backs proxy %s", id, p.ID)
		}
	}
	if _, ok := m.keys[id]; !ok {
		return fmt.Errorf("no such key")
	}
	delete(m.keys, id)
	return nil
}

// ---------------------------------------------------------------- proxies

// CreateProxies mints count tunnels keyed to keyID.
// CreateProxies creates count proxies for a key in the default location.
func (m *Manager) CreateProxies(keyID string, count, sessions int, name string) ([]*Proxy, error) {
	return m.CreateProxiesIn(keyID, count, sessions, name, "")
}

// CreateProxiesIn creates count proxies pinned to one country (ISO alpha-2 or a
// full location key). An empty location keeps HMA's default (nearest) choice.
func (m *Manager) CreateProxiesIn(keyID string, count, sessions int, name, location string) ([]*Proxy, error) {
	k := m.getKey(keyID)
	if k == nil {
		return nil, fmt.Errorf("no such key: %s", keyID)
	}
	if count <= 0 {
		count = 1
	}
	if count > 64 {
		count = 64
	}
	if sessions <= 0 {
		sessions = 1
	}

	out := make([]*Proxy, 0, count)
	for i := 0; i < count; i++ {
		p, err := m.createOne(k, sessions, name, location)
		if err != nil {
			// roll back what this call already created
			for _, q := range out {
				_ = m.DeleteProxy(q.ID)
			}
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (m *Manager) createOne(k *Key, sessions int, name, location string) (*Proxy, error) {
	m.mu.Lock()
	port, err := m.freePortLocked()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.seq++
	id := fmt.Sprintf("p%d-%s", m.seq, newID()[:6])
	if name != "" {
		name = fmt.Sprintf("%s-%d", name, m.seq)
	} else {
		name = fmt.Sprintf("t%d", m.seq-1)
	}
	p := &Proxy{
		ID:        id,
		Name:      name,
		KeyID:     k.ID,
		Country:   location,
		Port:      port,
		HTTPPort:  port + m.httpOffset,
		Sessions:  sessions,
		CreatedAt: time.Now(),
	}
	listenHost, httpOffset, auth := m.listenHost, m.httpOffset, m.auth
	m.proxies[id] = p
	m.mu.Unlock()

	fail := func(err error) (*Proxy, error) {
		m.mu.Lock()
		delete(m.proxies, id)
		m.mu.Unlock()
		for _, ln := range p.ln {
			_ = ln.Close()
		}
		if p.t != nil {
			p.t.Close()
		}
		return nil, err
	}

	p.t = &Tunnel{Name: name}
	base := TunnelConfig{Name: name, Port: p.Port, HTTPPort: p.HTTPPort, MTU: 1420}

	socksAddr := net.JoinHostPort(listenHost, strconv.Itoa(p.Port))
	ln, err := StartSocks5(socksAddr, p.t, auth)
	if err != nil {
		return fail(fmt.Errorf("socks5 %s: %w", socksAddr, err))
	}
	p.ln = append(p.ln, ln)
	p.Socks5 = proxyURL("socks5", auth, socksAddr)

	if httpOffset > 0 {
		httpAddr := net.JoinHostPort(listenHost, strconv.Itoa(p.HTTPPort))
		hln, err := StartHTTPProxy(httpAddr, p.t, auth)
		if err != nil {
			return fail(fmt.Errorf("http %s: %w", httpAddr, err))
		}
		p.ln = append(p.ln, hln)
		p.HTTP = proxyURL("http", auth, httpAddr)
	}

	mcfg := MintConfig{
		JWT:         k.Token(),
		Token:       k.Token,
		ProbeURL:    m.probeURL,
		Sessions:    sessions,
		LocationKey: location,
	}
	mcfg.defaults()

	p.sup = NewSupervisor(p.t, base, mcfg)
	p.sup.Start()

	log.Printf("[api] proxy %s up: %s %s", p.ID, p.Socks5, p.HTTP)
	return p, nil
}

func (m *Manager) freePortLocked() (int, error) {
	used := map[int]bool{}
	for _, p := range m.proxies {
		used[p.Port] = true
		used[p.HTTPPort] = true
	}
	for port := m.portBase; port < m.portBase+4000; port++ {
		if used[port] {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(m.listenHost, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no free port in %d..%d", m.portBase, m.portBase+4000)
}

func (m *Manager) getProxy(id string) *Proxy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.proxies[id]
}

func (m *Manager) ListProxies() []*Proxy {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Proxy, 0, len(m.proxies))
	for _, p := range m.proxies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func (m *Manager) DeleteProxy(id string) error {
	m.mu.Lock()
	p := m.proxies[id]
	delete(m.proxies, id)
	m.mu.Unlock()
	if p == nil {
		return fmt.Errorf("no such proxy")
	}
	if p.sup != nil {
		p.sup.Stop()
	}
	for _, ln := range p.ln {
		_ = ln.Close()
	}
	if p.t != nil {
		p.t.Close()
	}
	log.Printf("[api] proxy %s removed", id)
	return nil
}

// RenewAll asks every live tunnel to re-mint with the current token.
func (m *Manager) RenewAll() {
	for _, p := range m.ListProxies() {
		if p.sup != nil {
			p.sup.requestRenew()
		}
	}
}

// RotateProxy forces a fresh set of sessions, which usually yields a new exit IP.
func (m *Manager) RotateProxy(id string) error {
	p := m.getProxy(id)
	if p == nil {
		return fmt.Errorf("no such proxy")
	}
	if p.sup == nil {
		return fmt.Errorf("proxy has no supervisor")
	}
	p.sup.requestRenew()
	return nil
}

// Status returns the live view of one proxy.
func (m *Manager) Status(id string) (*ProxyStatus, error) {
	p := m.getProxy(id)
	if p == nil {
		return nil, fmt.Errorf("no such proxy")
	}
	return liveStatus(p), nil
}

// StatusAll returns the live view of every proxy.
func (m *Manager) StatusAll() []*ProxyStatus {
	ps := m.ListProxies()
	out := make([]*ProxyStatus, 0, len(ps))
	for _, p := range ps {
		out = append(out, liveStatus(p))
	}
	return out
}

func liveStatus(p *Proxy) *ProxyStatus {
	st := &ProxyStatus{
		ID:        p.ID,
		Name:      p.Name,
		KeyID:     p.KeyID,
		Country:   p.Country,
		Socks5:    p.Socks5,
		HTTP:      p.HTTP,
		Port:      p.Port,
		HTTPPort:  p.HTTPPort,
		Sessions:  p.Sessions,
		CreatedAt: p.CreatedAt,
		State:     "starting",
	}
	if p.t != nil {
		ts := p.t.Stats()
		st.Up = ts.Up || ts.LastHandshake > 0
		st.ExitIP = ts.ExitIP
		st.SessionCtip = ts.SessionCtip
		st.SessionAge = ts.SessionAge
		st.Remints = ts.Remints
		st.Hedges = ts.Hedges
		st.Dials = ts.Dials
		st.Errors = ts.Errors
		st.RxBytes = ts.RxBytes
		st.TxBytes = ts.TxBytes
		st.LastError = ts.LastError
		if st.Up {
			st.State = "up"
		} else {
			st.State = "down"
		}
	}
	return st
}

// Verify fetches the exit IP through the proxy's tunnel.
func (m *Manager) Verify(id string) (string, error) {
	p := m.getProxy(id)
	if p == nil {
		return "", fmt.Errorf("no such proxy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return p.t.GetExitIP(ctx, m.probeURL)
}

// Close stops everything.
func (m *Manager) Close() {
	for _, p := range m.ListProxies() {
		_ = m.DeleteProxy(p.ID)
	}
}
