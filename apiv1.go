package main

// External JSON API (/api/v1/*) for other programs: read the pool, create
// proxies, rotate, verify and delete them, and manage HMA keys.
//
// Auth:  Authorization: Bearer hmap_xxx   (or  X-API-Key: hmap_xxx)
// Scope: keys created with "Full Control" carry the write scope; read-only keys
// may only use GET endpoints and receive 403 on mutations.
//
//	GET    /api/v1/me                      key info + pool totals
//	GET    /api/v1/proxies                 list (?format=json|socks5|http)
//	POST   /api/v1/proxies                 {key_id?,count,sessions,country}
//	GET    /api/v1/proxies/{id}            one proxy
//	DELETE /api/v1/proxies/{id}
//	POST   /api/v1/proxies/{id}/rotate     new exit IP
//	GET    /api/v1/proxies/{id}/verify     exit IP through the tunnel
//	POST   /api/v1/proxies/bulk-delete     {ids:[...]}
//	POST   /api/v1/geo/refresh             re-measure country + ping
//	GET    /api/v1/countries               countries this key's token reaches
//	GET    /api/v1/keys                    HMA keys + status
//	POST   /api/v1/keys                    {name,token} add a key
//	DELETE /api/v1/keys/{id}
//	GET    /api/v1/settings
//	POST   /api/v1/settings

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// proxyView is the wire shape of one proxy: the core status plus live geo.
type proxyView struct {
	*ProxyStatus
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Flag        string `json:"flag,omitempty"`
	PingMs      int    `json:"ping_ms,omitempty"`
	ExitIP      string `json:"exit_ip,omitempty"`
}

// proxyViews returns every proxy enriched with cached geo/ping, sorted the way
// clients expect it: fastest first, proxies without a measurement last.
func (a *poolApp) proxyViews() []proxyView {
	proxies := a.mgr.StatusAll()
	geoByID := map[string]*geoInfo{}
	for _, p := range a.mgr.ListProxies() {
		if gi := a.geo.ensure(a.mgr, p); gi != nil {
			geoByID[p.ID] = gi
		}
	}
	views := make([]proxyView, 0, len(proxies))
	for _, p := range proxies {
		v := proxyView{ProxyStatus: p}
		v.ExitIP = p.ExitIP
		if gi := geoByID[p.ID]; gi != nil {
			v.Country = gi.Country
			v.CountryCode = gi.CountryCode
			v.Flag = gi.Flag
			v.PingMs = gi.PingMs
			if gi.ExitIP != "" {
				v.ExitIP = gi.ExitIP
			}
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool {
		pi, pj := views[i].PingMs, views[j].PingMs
		if pi <= 0 {
			pi = 1 << 30
		}
		if pj <= 0 {
			pj = 1 << 30
		}
		if pi != pj {
			return pi < pj
		}
		return views[i].Port < views[j].Port
	})
	return views
}

// ------------------------------------------------------------ auth

// bearerToken extracts an API key from the Authorization or X-API-Key header.
func bearerToken(r *http.Request) string {
	if h := strings.TrimSpace(r.Header.Get("Authorization")); h != "" {
		if parts := strings.SplitN(h, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// requireKey authenticates the request and records the use.
func (a *poolApp) requireKey(w http.ResponseWriter, r *http.Request) (*APIKey, bool) {
	k := a.state.VerifyAPIKey(bearerToken(r))
	if k == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="HMAProxyPool"`)
		writeErr(w, http.StatusUnauthorized, errString("invalid or missing API key"))
		return nil, false
	}
	a.state.TouchAPIKey(k.ID)
	a.persistAPIUsage()
	return k, true
}

// persistAPIUsage saves last-used counters at most every 20 seconds so a busy
// client does not rewrite pool.json on every request.
func (a *poolApp) persistAPIUsage() {
	a.apiMu.Lock()
	due := time.Since(a.apiSavedAt) > 20*time.Second
	if due {
		a.apiSavedAt = time.Now()
	}
	a.apiMu.Unlock()
	if due {
		a.save()
	}
}

// apiV1 is the single entry point for /api/v1/*.
func (a *poolApp) apiV1(w http.ResponseWriter, r *http.Request) {
	k, ok := a.requireKey(w, r)
	if !ok {
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	rest := strings.TrimPrefix(path, "/api/v1")
	rest = strings.TrimPrefix(rest, "/")

	// Write guard: everything that is not a GET needs the write scope.
	if r.Method != http.MethodGet && !k.CanWrite() {
		writeErr(w, http.StatusForbidden, errString("this API key is read-only"))
		return
	}

	switch {
	case rest == "" || rest == "me":
		a.apiMe(w, r, k)
	case rest == "proxies":
		a.apiProxies(w, r, k)
	case rest == "proxies/bulk-delete":
		a.apiBulkDelete(w, r)
	case strings.HasPrefix(rest, "proxies/"):
		a.apiProxyItem(w, r, strings.TrimPrefix(rest, "proxies/"))
	case rest == "geo/refresh":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, errString("POST"))
			return
		}
		a.geo.refreshAll(a.mgr)
		writeJSON(w, http.StatusOK, map[string]bool{"refreshing": true})
	case rest == "countries":
		a.apiCountries(w, r)
	case rest == "keys":
		a.apiKeysV1(w, r)
	case strings.HasPrefix(rest, "keys/"):
		a.apiKeyItemV1(w, r, strings.TrimPrefix(rest, "keys/"))
	case rest == "settings":
		a.apiSettings(w, r)
	default:
		writeErr(w, http.StatusNotFound, errString("unknown endpoint"))
	}
}

// ------------------------------------------------------------ handlers

func (a *poolApp) apiMe(w http.ResponseWriter, r *http.Request, k *APIKey) {
	views := a.proxyViews()
	up := 0
	for _, p := range views {
		if p.Up {
			up++
		}
	}
	scopes := append([]string(nil), k.Scopes...)
	writeJSON(w, http.StatusOK, map[string]any{
		"key": map[string]any{
			"id": k.ID, "name": k.Name, "prefix": k.Prefix,
			"scopes": scopes, "can_write": k.CanWrite(),
			"requests": k.Requests + 1,
		},
		"pool": map[string]int{
			"proxies": len(views), "up": up, "down": len(views) - up,
		},
		"version": a.version,
	})
}

func (a *poolApp) apiProxies(w http.ResponseWriter, r *http.Request, k *APIKey) {
	switch r.Method {
	case http.MethodGet:
		views := a.proxyViews()
		// Optional filters.
		if st := strings.ToLower(r.URL.Query().Get("state")); st != "" {
			filtered := views[:0]
			for _, p := range views {
				if (st == "up" && p.Up) || (st == "down" && !p.Up) {
					filtered = append(filtered, p)
				}
			}
			views = filtered
		}
		if cc := strings.ToUpper(r.URL.Query().Get("country")); cc != "" {
			filtered := views[:0]
			for _, p := range views {
				if p.CountryCode == cc || p.Country == cc || p.ProxyStatus.Country == cc {
					filtered = append(filtered, p)
				}
			}
			views = filtered
		}
		switch strings.ToLower(r.URL.Query().Get("format")) {
		case "socks5", "http", "lines", "plain", "txt", "text":
			scheme := "socks5"
			if strings.EqualFold(r.URL.Query().Get("format"), "http") {
				scheme = "http"
			}
			// ?host= rewrites the endpoint host so the output is usable from a
			// different machine (the listeners bind to 0.0.0.0 / 127.0.0.1).
			host := strings.TrimSpace(r.URL.Query().Get("host"))
			if host != "" {
				host = stripPort(host)
			}
			user, pass := a.mgr.Auth().User, a.mgr.Auth().Pass
			var b strings.Builder
			for _, p := range views {
				if host != "" {
					port := p.Port
					if scheme == "http" {
						port = p.HTTPPort
					}
					if line := proxyLine(scheme, host, port, user, pass); line != "" {
						b.WriteString(line)
						b.WriteByte('\n')
					}
					continue
				}
				u := p.Socks5
				if scheme == "http" {
					u = p.HTTP
				}
				if u == "" {
					continue
				}
				b.WriteString(u)
				b.WriteByte('\n')
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(b.String()))
		default:
			writeJSON(w, http.StatusOK, map[string]any{
				"count": len(views), "proxies": views,
			})
		}

	case http.MethodPost:
		var body struct {
			KeyID    string `json:"key_id"`
			Count    int    `json:"count"`
			Sessions int    `json:"sessions"`
			Country  string `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		keyID, count, sessions, country, err := a.normalizeCreate(
			body.KeyID, body.Count, body.Sessions, body.Country)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		a.startCreate(keyID, count, sessions, country)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"queued": true, "key_id": keyID, "count": count,
			"sessions": sessions, "country": country,
		})

	default:
		writeErr(w, http.StatusMethodNotAllowed, errString("GET or POST"))
	}
}

func (a *poolApp) apiProxyItem(w http.ResponseWriter, r *http.Request, rest string) {
	switch {
	case strings.HasSuffix(rest, "/rotate"):
		id := strings.TrimSuffix(rest, "/rotate")
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, errString("POST"))
			return
		}
		if err := a.mgr.RotateProxy(id); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "rotated": true})
	case strings.HasSuffix(rest, "/verify"):
		id := strings.TrimSuffix(rest, "/verify")
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, errString("GET"))
			return
		}
		ip, err := a.mgr.Verify(id)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "exit_ip": ip})
	default:
		id := rest
		if id == "" {
			writeErr(w, http.StatusNotFound, errString("proxy id required"))
			return
		}
		switch r.Method {
		case http.MethodGet:
			for _, p := range a.proxyViews() {
				if p.ID == id {
					writeJSON(w, http.StatusOK, p)
					return
				}
			}
			writeErr(w, http.StatusNotFound, errString("no such proxy"))
		case http.MethodDelete:
			a.deleteProxyByID(w, id)
		default:
			writeErr(w, http.StatusMethodNotAllowed, errString("GET or DELETE"))
		}
	}
}

// deleteProxyByID removes one proxy and keeps the key's plan in sync.
func (a *poolApp) deleteProxyByID(w http.ResponseWriter, id string) {
	p, err := a.mgr.Status(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err := a.mgr.DeleteProxy(id); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if sk := a.state.getKey(p.KeyID); sk != nil {
		if len(sk.PlanCountries) > 0 {
			sk.PlanCountries = consumePlanCountry(sk.PlanCountries, p.Country, 1)
		}
		if sk.PlanCount > 0 {
			sk.PlanCount--
		}
		a.save()
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

func (a *poolApp) apiBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errString("POST"))
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	deleted, byKey, byKeyCountry := a.deleteProxies(body.IDs)
	a.adjustPlans(byKey, byKeyCountry)
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

func (a *poolApp) apiCountries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errString("GET"))
		return
	}
	keyID := r.URL.Query().Get("key_id")
	var tok string
	if keyID != "" {
		if k := a.mgr.getKey(keyID); k != nil {
			tok = k.Token()
		}
	} else {
		for _, k := range a.mgr.ListKeys() {
			if k.Token() != "" {
				tok = k.Token()
				break
			}
		}
	}
	if tok == "" {
		writeErr(w, http.StatusBadRequest, errString("no HMA key registered"))
		return
	}
	list, err := CountryDiscovery(tok)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"countries": list, "count": len(list)})
}

func (a *poolApp) apiKeysV1(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		proxies := a.mgr.StatusAll()
		byKey := map[string]int{}
		for _, p := range proxies {
			byKey[p.KeyID]++
		}
		out := make([]map[string]any, 0, len(a.state.Keys))
		for _, sk := range a.state.Keys {
			item := map[string]any{
				"id": sk.ID, "name": sk.Name, "proxies": byKey[sk.ID],
				"plan_count": sk.PlanCount, "plan_sessions": sk.PlanSessions,
			}
			if k := a.mgr.getKey(sk.ID); k != nil {
				item["status"] = k.Status
				item["note"] = k.Note
				if !k.ExpiresAt.IsZero() {
					item["expires_at"] = k.ExpiresAt.Format(time.RFC3339)
				}
			} else {
				item["status"] = "not-loaded"
			}
			out = append(out, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": out, "count": len(out)})

	case http.MethodPost:
		var body struct {
			Name  string `json:"name"`
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		body.Token = strings.TrimSpace(body.Token)
		if body.Name == "" {
			body.Name = "api-" + time.Now().Format("0102-150405")
		}
		if _, ok := jwtExpiry(body.Token); !ok {
			writeErr(w, http.StatusBadRequest, errString("token does not look like a JWT"))
			return
		}
		k, err := a.mgr.AddKey(body.Name, body.Token)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		a.state.upsertKey(StoredKey{ID: k.ID, Name: k.Name, Token: body.Token, AddedAt: time.Now()})
		a.save()
		writeJSON(w, http.StatusOK, map[string]any{"id": k.ID, "name": k.Name, "note": k.Note})

	default:
		writeErr(w, http.StatusMethodNotAllowed, errString("GET or POST"))
	}
}

func (a *poolApp) apiKeyItemV1(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, errString("DELETE"))
		return
	}
	if err := a.mgr.DeleteKey(id); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	a.state.deleteKey(id)
	a.save()
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (a *poolApp) apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"settings": a.state.Settings})
	case http.MethodPost:
		var body settingsBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		rebuild, err := a.applySettings(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"saved": true, "settings": a.state.Settings, "rebuild_required": rebuild,
		})
	default:
		writeErr(w, http.StatusMethodNotAllowed, errString("GET or POST"))
	}
}

// apiIndex documented the endpoints; the live list now lives in the dashboard
// APIs tab and API.md (the endpoint itself requires a key).
