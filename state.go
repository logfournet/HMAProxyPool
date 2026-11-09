package main

// AppState is what HMAProxyPool persists across restarts: the dashboard
// password hash, runtime settings and the registered keys (tokens). Proxies
// are ephemeral tunnels; the per-key PlanCount/PlanSessions below are replayed
// on boot so a "pool" comes back the way it was left.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// PlanCountry is one line of a key's country plan: "keep N proxies in Code".
type PlanCountry struct {
	Code  string `json:"code"` // "" = HMA default location
	Count int    `json:"count"`
}

// StoredKey is a saved key with its desired pool size.
type StoredKey struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Token         string        `json:"token"`
	AddedAt       time.Time     `json:"added_at"`
	PlanCount     int           `json:"plan_count,omitempty"`    // proxies to keep for this key
	PlanSessions  int           `json:"plan_sessions,omitempty"` // sessions per proxy
	PlanCountries []PlanCountry `json:"plan_countries,omitempty"`
}

type Settings struct {
	PortBase   int    `json:"port_base"`
	HTTPOffset int    `json:"http_offset"`
	Sessions   int    `json:"sessions"`
	ProbeURL   string `json:"probe_url"`
	AutoProxies int   `json:"auto_proxies,omitempty"` // unused; PlanCount lives on keys
	TokenFile  string `json:"token_file,omitempty"`   // watched JWT file (jwt.txt etc.)

	// ListenHost is the interface every proxy listener binds to:
	// "127.0.0.1" (loopback only) or "0.0.0.0" (reachable from the network).
	ListenHost string `json:"listen_host,omitempty"`
	// ProxyUser/ProxyPass are shared by every SOCKS5 and HTTP proxy in the pool.
	// Both empty = no authentication (open proxy).
	ProxyUser string `json:"proxy_user,omitempty"`
	ProxyPass string `json:"proxy_pass,omitempty"`
}

type AppState struct {
	PasswordHash string     `json:"password_hash"`
	Settings     Settings   `json:"settings"`
	Keys         []StoredKey `json:"keys"`
	APIKeys      []APIKey   `json:"api_keys,omitempty"`
}

func defaultSettings() Settings {
	return Settings{
		PortBase:   3000,
		HTTPOffset: 1000,
		Sessions:   1,
		ProbeURL:   "https://icanhazip.com/",
		ListenHost: "127.0.0.1",
	}
}

// loadState reads pool.json if present.
func loadState(path string) (*AppState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AppState{Settings: defaultSettings()}, nil
		}
		return nil, err
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) // tolerate BOM
	var st AppState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if st.Settings.PortBase == 0 {
		st.Settings = defaultSettings()
	}
	if st.Settings.ListenHost == "" {
		st.Settings.ListenHost = "127.0.0.1"
	}
	if st.Keys == nil {
		st.Keys = []StoredKey{}
	}
	if st.APIKeys == nil {
		st.APIKeys = []APIKey{}
	}
	return &st, nil
}

// saveState atomically writes pool.json.
func (a *AppState) save(path string) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// setPassword hashes and stores pw; returns the plaintext only for first-run.
func (a *AppState) setPassword(pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.PasswordHash = string(h)
	return nil
}

func (a *AppState) checkPassword(pw string) bool {
	if a.PasswordHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(pw)) == nil
}

func (a *AppState) getKey(id string) *StoredKey {
	for i := range a.Keys {
		if a.Keys[i].ID == id {
			return &a.Keys[i]
		}
	}
	return nil
}

func (a *AppState) upsertKey(k StoredKey) {
	for i := range a.Keys {
		if a.Keys[i].ID == k.ID {
			a.Keys[i] = k
			return
		}
	}
	a.Keys = append(a.Keys, k)
}

func (a *AppState) deleteKey(id string) bool {
	for i := range a.Keys {
		if a.Keys[i].ID == id {
			a.Keys = append(a.Keys[:i], a.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// ensurePassword returns the plaintext password to show on first run (when no
// password was provided and none is stored), or "" when already set.
func (a *AppState) ensurePassword(provided string) (string, error) {
	if provided != "" {
		if err := a.setPassword(provided); err != nil {
			return "", err
		}
		return "", nil
	}
	if a.PasswordHash != "" {
		return "", nil
	}
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	pw := hex.EncodeToString(buf)
	if err := a.setPassword(pw); err != nil {
		return "", err
	}
	return pw, nil
}

// restoreKeys re-registers every stored key in the manager under its original
// ID and schedules the planned proxy pools to come back.
func (a *AppState) restoreKeys(mgr *Manager) int {
	for _, sk := range a.Keys {
		mgr.restoreKey(sk.ID, sk.Name, sk.Token)
		// Country plan (preferred): replay one batch per country.
		if len(sk.PlanCountries) > 0 {
			for _, pc := range sk.PlanCountries {
				if pc.Count <= 0 {
					continue
				}
				go func(sk StoredKey, code string, n int) {
					_, err := mgr.CreateProxiesIn(sk.ID, n, sk.PlanSessions, sk.Name, code)
					if err != nil {
						log.Printf("[state] restore %d proxies for %s in %s: %v", n, sk.ID, code, err)
					} else {
						log.Printf("[state] restored %d proxy(ies) for key %s in %s", n, sk.ID, code)
					}
				}(sk, pc.Code, pc.Count)
			}
			continue
		}
		if sk.PlanCount > 0 {
			go func(sk StoredKey) {
				_, err := mgr.CreateProxies(sk.ID, sk.PlanCount, sk.PlanSessions, sk.Name)
				if err != nil {
					log.Printf("[state] restore %d proxies for %s: %v", sk.PlanCount, sk.ID, err)
				} else {
					log.Printf("[state] restored %d proxy(ies) for key %s", sk.PlanCount, sk.ID)
				}
			}(sk)
		}
	}
	return len(a.Keys)
}
