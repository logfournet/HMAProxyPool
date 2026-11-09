package main

// Per-proxy country + latency ("ping") for the dashboard.
//
// Country is looked up from the tunnel's live exit IP via ipwho.is (host-side
// HTTPS — it only names the IP string, it never routes through the proxy).
// Ping is the measured TCP-connect latency through the tunnel to a stable
// target (Cloudflare 1.1.1.1:443), i.e. how fast the exit actually responds.
// Results are cached per proxy and refreshed lazily (on overview when stale)
// and on demand via POST /api/geo/refresh.

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	pingTarget     = "1.1.1.1:443"
	geoStaleAfter  = 120 * time.Second
	geoFetchTimeout = 8 * time.Second
)

type geoInfo struct {
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"` // ISO alpha-2, used for flag images
	Flag        string `json:"flag,omitempty"`
	PingMs      int    `json:"ping_ms,omitempty"`
	ExitIP      string `json:"exit_ip,omitempty"`
}

type geoStore struct {
	mu   sync.Mutex
	m    map[string]*geoInfo
	upd  map[string]time.Time
	busy map[string]bool
}

func newGeoStore() *geoStore {
	return &geoStore{
		m:    map[string]*geoInfo{},
		upd:  map[string]time.Time{},
		busy: map[string]bool{},
	}
}

func (g *geoStore) get(id string) (*geoInfo, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.m[id]
	return v, ok
}

// stale reports whether id has no cached value or it is older than geoStaleAfter.
func (g *geoStore) stale(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	u, ok := g.upd[id]
	return !ok || time.Since(u) > geoStaleAfter
}

// put stores a fresh value.
func (g *geoStore) put(id string, v *geoInfo) {
	g.mu.Lock()
	g.m[id] = v
	g.upd[id] = time.Now()
	g.busy[id] = false
	g.mu.Unlock()
}

// refresh computes country + ping for one proxy (blocking, up to ~25 s).
func (g *geoStore) refresh(mgr *Manager, p *Proxy) *geoInfo {
	info := &geoInfo{}
	if ip, err := mgr.Verify(p.ID); err == nil && ip != "" {
		if v := lookupGeo(ip); v != nil {
			info = v
		}
		info.ExitIP = ip
	}
	if p.t != nil {
		pctx, cancel := context.WithTimeout(context.Background(), geoFetchTimeout)
		st := time.Now()
		if c, err := p.t.DialContext(pctx, "tcp", pingTarget); err == nil {
			_ = c.Close()
			info.PingMs = int(time.Since(st).Milliseconds())
		}
		cancel()
	}
	return info
}

// refreshAsync runs refresh in the background, one at a time per proxy.
func (g *geoStore) refreshAsync(mgr *Manager, p *Proxy) {
	g.mu.Lock()
	if g.busy[p.ID] {
		g.mu.Unlock()
		return
	}
	g.busy[p.ID] = true
	g.mu.Unlock()

	go func() {
		v := g.refresh(mgr, p)
		g.put(p.ID, v)
		log.Printf("[geo] %s -> %s %s ping=%dms", p.ID, v.Flag, v.Country, v.PingMs)
	}()
}

// ensure pulls a fresh value when the cache is stale.
func (g *geoStore) ensure(mgr *Manager, p *Proxy) *geoInfo {
	if v, ok := g.get(p.ID); ok && !g.stale(p.ID) {
		return v
	}
	g.refreshAsync(mgr, p)
	if v, ok := g.get(p.ID); ok {
		return v
	}
	return nil
}

// refreshAll re-computes every proxy's geo in the background.
func (g *geoStore) refreshAll(mgr *Manager) {
	for _, p := range mgr.ListProxies() {
		g.refreshAsync(mgr, p)
	}
}

// lookupGeo asks ipwho.is for the country/flag of an IP.
func lookupGeo(ip string) *geoInfo {
	if ip == "" {
		return nil
	}
	req, err := http.NewRequest("GET", "https://ipwho.is/"+ip, nil)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: geoFetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil
	}
	var d struct {
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Flag        struct {
			Emoji string `json:"emoji"`
		} `json:"flag"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil
	}
	if d.Country == "" {
		return nil
	}
	return &geoInfo{Country: d.Country, CountryCode: d.CountryCode, Flag: d.Flag.Emoji}
}
