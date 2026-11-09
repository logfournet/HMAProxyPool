package main

// API keys let other programs drive the pool without the dashboard cookie.
//
// A key is a bearer token ("hmap_<48 hex>"). Only its SHA-256 hash is stored in
// pool.json, so a leaked state file cannot be replayed, and the plaintext is
// shown exactly once at creation.
//
// Scopes:
//   read   list proxies / countries / keys / settings
//   write  create, rotate and delete proxies (added with "Full Control")
//
// The dashboard manages keys under /api/apikeys (cookie session); external
// clients use /api/v1/* with Authorization: Bearer <key> (see apiv1.go).

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// APIKey is a persisted client credential.
type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"` // leading chars, safe to show
	Token     string    `json:"token"`  // full token, revealed in the dashboard
	Hash      string    `json:"hash"`   // sha256(token) hex
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitempty"`
	Requests  int64     `json:"requests,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// CanWrite reports whether the key may mutate the pool.
func (k *APIKey) CanWrite() bool {
	for _, s := range k.Scopes {
		if s == "write" {
			return true
		}
	}
	return false
}

// CanRead always holds for a live key.
func (k *APIKey) CanRead() bool { return true }

const apiTokenPrefix = "hmap_"

// hashAPIKey is the at-rest representation of a key.
func hashAPIKey(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// apiKeysMu guards AppState.APIKeys (reads and writes happen from request
// handlers that run concurrently).
var apiKeysMu sync.Mutex

// CreateAPIKey mints a token and returns it together with its stored record.
// The plaintext token is kept so the dashboard can show it again later.
func (a *AppState) CreateAPIKey(name string, write bool) (string, APIKey) {
	var raw [24]byte
	_, _ = rand.Read(raw[:])
	tok := apiTokenPrefix + hex.EncodeToString(raw[:])

	name = strings.TrimSpace(name)
	if name == "" {
		name = "client-" + time.Now().Format("01-02-150405")
	}
	scopes := []string{"read"}
	if write {
		scopes = append(scopes, "write")
	}
	k := APIKey{
		ID:        newID(),
		Name:      name,
		Prefix:    tok[:14],
		Token:     tok,
		Hash:      hashAPIKey(tok),
		Scopes:    scopes,
		CreatedAt: time.Now(),
	}
	apiKeysMu.Lock()
	a.APIKeys = append(a.APIKeys, k)
	apiKeysMu.Unlock()
	return tok, k
}

// VerifyAPIKey returns the live key matching tok, or nil. The comparison is
// constant-time so a wrong token cannot be narrowed down by timing.
func (a *AppState) VerifyAPIKey(tok string) *APIKey {
	tok = strings.TrimSpace(tok)
	if !strings.HasPrefix(tok, apiTokenPrefix) {
		return nil
	}
	h := hashAPIKey(tok)
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()
	for i := range a.APIKeys {
		k := &a.APIKeys[i]
		if k.Revoked || k.Hash == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(k.Hash), []byte(h)) == 1 {
			cp := *k
			return &cp
		}
	}
	return nil
}

// TouchAPIKey records a successful use.
func (a *AppState) TouchAPIKey(id string) {
	apiKeysMu.Lock()
	for i := range a.APIKeys {
		if a.APIKeys[i].ID == id {
			a.APIKeys[i].Requests++
			a.APIKeys[i].LastUsed = time.Now()
			break
		}
	}
	apiKeysMu.Unlock()
}

// ListAPIKeys returns a copy, newest first.
func (a *AppState) ListAPIKeys() []APIKey {
	apiKeysMu.Lock()
	out := make([]APIKey, len(a.APIKeys))
	copy(out, a.APIKeys)
	apiKeysMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// DeleteAPIKey removes a key by ID (or by its display prefix).
func (a *AppState) DeleteAPIKey(id string) bool {
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()
	for i := range a.APIKeys {
		if a.APIKeys[i].ID == id || a.APIKeys[i].Prefix == id {
			a.APIKeys = append(a.APIKeys[:i], a.APIKeys[i+1:]...)
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- dashboard

type apiKeyView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	Token     string `json:"token"`
	Scopes    string `json:"scopes"` // "Read + Write" | "Read Only"
	CreatedAt string `json:"created_at"`
	LastUsed  string `json:"last_used,omitempty"`
	Requests  int64  `json:"requests"`
}

func toAPIKeyView(k APIKey) apiKeyView {
	v := apiKeyView{
		ID: k.ID, Name: k.Name, Prefix: k.Prefix, Token: k.Token, Requests: k.Requests,
		CreatedAt: k.CreatedAt.Format(time.RFC3339),
		Scopes:    "Read Only",
	}
	if k.CanWrite() {
		v.Scopes = "Read + Write"
	}
	if !k.LastUsed.IsZero() {
		v.LastUsed = k.LastUsed.Format(time.RFC3339)
	}
	return v
}

// apiKeys handles GET (list) and POST (create) for the dashboard.
func (a *poolApp) apiKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ks := a.state.ListAPIKeys()
		out := make([]apiKeyView, 0, len(ks))
		for _, k := range ks {
			out = append(out, toAPIKeyView(k))
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": out, "count": len(out)})
	case http.MethodPost:
		var body struct {
			Name  string `json:"name"`
			Write *bool  `json:"write"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		write := true
		if body.Write != nil {
			write = *body.Write
		}
		tok, k := a.state.CreateAPIKey(body.Name, write)
		a.save()
		writeJSON(w, http.StatusOK, map[string]any{
			"token": tok,
			"key":   toAPIKeyView(k),
		})
	default:
		writeErr(w, http.StatusMethodNotAllowed, errString("GET or POST"))
	}
}

// apiKeyItem deletes one key (DELETE /api/apikeys/{id}).
func (a *poolApp) apiKeyItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, errString("DELETE"))
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/apikeys/"), "/")
	if id == "" || !a.state.DeleteAPIKey(id) {
		writeErr(w, http.StatusNotFound, errString("no such API key"))
		return
	}
	a.save()
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
