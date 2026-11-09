package main

// Small extensions on the copied Manager so the dashboard can change runtime
// knobs without a restart.

import (
	"log"
	"net/url"
	"time"
)

// proxyURL builds "scheme://[user:pass@]host:port" for display and clients.
func proxyURL(scheme string, auth ProxyAuth, hostport string) string {
	if !auth.enabled() {
		return scheme + "://" + hostport
	}
	u := url.UserPassword(auth.User, auth.Pass)
	return scheme + "://" + u.String() + "@" + hostport
}

// SetAuth changes the shared proxy credential. It only affects proxies created
// afterwards (live listeners keep the credential they were started with), so
// callers that want it applied immediately rebuild the pool.
func (m *Manager) SetAuth(user, pass string) {
	m.mu.Lock()
	m.auth = ProxyAuth{User: user, Pass: pass}
	m.mu.Unlock()
}

// SetListenHost changes the interface new proxy listeners bind to.
func (m *Manager) SetListenHost(host string) {
	if host == "" {
		host = "127.0.0.1"
	}
	m.mu.Lock()
	m.listenHost = host
	m.mu.Unlock()
}

// Auth returns the current shared proxy credential.
func (m *Manager) Auth() ProxyAuth {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.auth
}

// ListenHost returns the current bind host.
func (m *Manager) ListenHost() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listenHost
}

// SetPortBase changes the SOCKS5 base and HTTP offset for future proxies.
func (m *Manager) SetPortBase(base, offset int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if base > 0 {
		m.portBase = base
	}
	if offset >= 0 {
		m.httpOffset = offset
	}
}

// SetProbeURL changes the URL used for liveness checks and exit-IP verification.
func (m *Manager) SetProbeURL(u string) {
	m.mu.Lock()
	m.probeURL = u
	m.mu.Unlock()
}

// restoreKey registers a persisted key under its original ID (so its stored
// proxy plan can be replayed). Unlike AddKey it is best-effort: a token that
// fails discovery is still registered and flagged, because the token-file feed
// may refresh it right after startup.
func (m *Manager) restoreKey(id, name, token string) *Key {
	k := &Key{ID: id, Name: name, AddedAt: time.Now(), Status: "ok", Note: "restored"}
	k.SetToken(token)
	if _, err := Discovery(token); err != nil {
		k.Status = "invalid"
		k.Note = "discovery rejected on restore: " + err.Error()
	}
	m.mu.Lock()
	m.keys[id] = k
	m.mu.Unlock()
	log.Printf("[api] key %s restored (%s)", k.ID, k.Note)
	return k
}
