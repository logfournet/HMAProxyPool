package main

// HTTP dashboard + JSON API for the proxy pool.
//
//	GET  /                 -> embedded SPA (index.html)
//	POST /api/login        {password}
//	POST /api/logout
//	GET  /api/me           -> {authed, version}
//	GET  /api/overview     -> keys + proxies + settings (polled by the UI)
//	POST /api/keys         {name, token}          add / validate a key
//	POST /api/keys/import  {}                     (Windows) pull from HMA service
//	DELETE /api/keys/{id}                         remove a key
//	POST /api/keys/{id}/token {token}             rotate a key's token
//	POST /api/proxies      {key_id,count,sessions} create proxies
//	DELETE /api/proxies/{id}
//	POST /api/proxies/{id}/rotate
//	GET  /api/proxies/{id}/verify
//	POST /api/settings     {port_base,http_offset,sessions,probe_url,token_file}
//	GET  /healthz

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type poolApp struct {
	mgr       *Manager
	state     *AppState
	statePath string
	version   string

	sessMu   sync.Mutex
	sessions map[string]time.Time

	geo *geoStore

	tokenStop   func()
	tokenFile   string
	sessDefault int

	apiMu      sync.Mutex
	apiSavedAt time.Time
}

func newPoolApp(mgr *Manager, st *AppState, statePath, version string) *poolApp {
	return &poolApp{
		mgr:       mgr,
		state:     st,
		statePath: statePath,
		version:   version,
		sessions:  map[string]time.Time{},
		geo:       newGeoStore(),
	}
}

// save persists state (safe to call from handlers).
func (a *poolApp) save() {
	if err := a.state.save(a.statePath); err != nil {
		log.Printf("[web] save state: %v", err)
	}
}

// ------------------------------------------------------------ auth

func (a *poolApp) sessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (a *poolApp) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !a.state.checkPassword(body.Password) {
		writeErr(w, http.StatusUnauthorized, errString("wrong password"))
		return
	}
	id := a.sessionID()
	a.sessMu.Lock()
	a.sessions[id] = time.Now().Add(24 * time.Hour)
	a.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "pool_session", Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authed": true})
}

func (a *poolApp) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("pool_session"); err == nil {
		a.sessMu.Lock()
		delete(a.sessions, c.Value)
		a.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "pool_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"authed": false})
}

func (a *poolApp) authed(r *http.Request) bool {
	c, err := r.Cookie("pool_session")
	if err != nil {
		return false
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	exp, ok := a.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}

// auth wraps a handler, requiring a valid session.
func (a *poolApp) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			writeErr(w, http.StatusUnauthorized, errString("login required"))
			return
		}
		next(w, r)
	}
}

// ------------------------------------------------------------ handlers

func (a *poolApp) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authed":  a.authed(r),
		"version": a.version,
		"platform": platformName(),
	})
}

func (a *poolApp) overview(w http.ResponseWriter, r *http.Request) {
	type keyView struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Status    string `json:"status"`
		Note      string `json:"note"`
		ExpiresAt string `json:"expires_at,omitempty"`
		AddedAt   string `json:"added_at"`
		PlanCount int    `json:"plan_count"`
		Proxies   int    `json:"proxies"`
	}
	// proxyView wraps the copied core ProxyStatus with live geo/latency data
	// so the core type itself stays untouched.
	proxies := a.mgr.StatusAll()
	byKey := map[string]int{}
	for _, p := range proxies {
		byKey[p.KeyID]++
	}
	keys := make([]keyView, 0, len(a.state.Keys))
	for _, sk := range a.state.Keys {
		kv := keyView{
			ID: sk.ID, Name: sk.Name, AddedAt: sk.AddedAt.Format(time.RFC3339),
			PlanCount: sk.PlanCount, Proxies: byKey[sk.ID],
		}
		if k := a.mgr.getKey(sk.ID); k != nil {
			kv.Status = k.Status
			kv.Note = k.Note
			if !k.ExpiresAt.IsZero() {
				kv.ExpiresAt = k.ExpiresAt.Format(time.RFC3339)
			}
		} else {
			kv.Status = "not-loaded"
			kv.Note = "key failed to load — check token"
		}
		keys = append(keys, kv)
	}
	views := a.proxyViews()
	up := 0
	for _, p := range proxies {
		if p.Up {
			up++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"keys":    keys,
		"proxies": views,
		"totals": map[string]int{
			"proxies": len(proxies), "up": up, "down": len(proxies) - up, "keys": len(keys),
		},
		"settings": a.state.Settings,
		"now":      time.Now().Format(time.RFC3339),
	})
}

// refreshGeo recomputes country + ping for every proxy on demand.
func (a *poolApp) refreshGeo(w http.ResponseWriter, r *http.Request) {
	a.geo.refreshAll(a.mgr)
	writeJSON(w, http.StatusOK, map[string]bool{"refreshing": true})
}

// rebuildProxies recreates every proxy with the current listen host and shared
// credential. Listeners bind at creation, so this is how a Settings change
// (bind address, proxy user/password) reaches proxies that are already up.
func (a *poolApp) rebuildProxies(w http.ResponseWriter, r *http.Request) {
	old := a.mgr.ListProxies()
	type item struct {
		keyID, country string
		sessions       int
	}
	plan := make([]item, 0, len(old))
	for _, p := range old {
		plan = append(plan, item{keyID: p.KeyID, country: p.Country, sessions: p.Sessions})
	}
	for _, p := range old {
		_ = a.mgr.DeleteProxy(p.ID)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true, "count": len(plan)})

	go func() {
		for _, it := range plan {
			if _, err := a.mgr.CreateProxiesIn(it.keyID, 1, it.sessions, "", it.country); err != nil {
				log.Printf("[web] rebuild (%s/%s): %v", it.keyID, it.country, err)
			}
		}
		log.Printf("[web] rebuilt %d proxies", len(plan))
	}()
}

func (a *poolApp) addKey(w http.ResponseWriter, r *http.Request) {
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
		body.Name = "key-" + time.Now().Format("150405")
	}
	if body.Token == "" {
		writeErr(w, http.StatusBadRequest, errString("token is required"))
		return
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
	sk := StoredKey{ID: k.ID, Name: k.Name, Token: body.Token, AddedAt: time.Now()}
	a.state.upsertKey(sk)
	a.save()
	writeJSON(w, http.StatusOK, map[string]any{"id": k.ID, "name": k.Name, "note": k.Note})
}

func (a *poolApp) importKey(w http.ResponseWriter, r *http.Request) {
	tok, err := ImportTokenFromService()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	k, err := a.mgr.AddKey("imported", tok)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sk := StoredKey{ID: k.ID, Name: k.Name, Token: tok, AddedAt: time.Now()}
	a.state.upsertKey(sk)
	a.save()
	writeJSON(w, http.StatusOK, map[string]any{"id": k.ID, "name": k.Name, "note": k.Note})
}

func (a *poolApp) deleteKey(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeErr(w, http.StatusNotFound, errString("not found"))
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

func (a *poolApp) setKeyToken(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	id = strings.TrimSuffix(id, "/token")
	if id == "" {
		writeErr(w, http.StatusNotFound, errString("not found"))
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	if _, ok := jwtExpiry(body.Token); !ok {
		writeErr(w, http.StatusBadRequest, errString("token does not look like a JWT"))
		return
	}
	if err := a.mgr.SetToken(id, body.Token); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if sk := a.state.getKey(id); sk != nil {
		sk.Token = body.Token
		a.save()
	}
	a.mgr.RenewAll()
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "updated": describeToken(body.Token)})
}

func (a *poolApp) createProxies(w http.ResponseWriter, r *http.Request) {
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
}

// normalizeCreate validates a create request and fills in its defaults.
func (a *poolApp) normalizeCreate(keyID string, count, sessions int, country string) (string, int, int, string, error) {
	country = strings.ToUpper(strings.TrimSpace(country))
	if country == "ANY" || country == "AUTO" {
		country = ""
	}
	if country != "" {
		if len(country) < 2 {
			return "", 0, 0, "", errString("country must be an ISO alpha-2 code (e.g. US)")
		}
		if k := a.mgr.getKey(keyID); k != nil {
			if _, err := DiscoveryIn(k.Token(), country); err != nil {
				return "", 0, 0, "", fmt.Errorf("country %s is not available: %w", country, err)
			}
		}
	}
	if keyID == "" {
		if len(a.state.Keys) == 1 {
			keyID = a.state.Keys[0].ID
		} else {
			return "", 0, 0, "", errString("key_id required (or register exactly one key)")
		}
	}
	if count <= 0 {
		count = 1
	}
	if count > 64 {
		count = 64
	}
	if sessions <= 0 {
		sessions = a.state.Settings.Sessions
		if sessions <= 0 {
			sessions = 1
		}
	}
	return keyID, count, sessions, country, nil
}

// startCreate mints the proxies in the background and records them in the key's
// plan so they come back after a restart.
func (a *poolApp) startCreate(keyID string, count, sessions int, country string) {
	go func() {
		ps, err := a.mgr.CreateProxiesIn(keyID, count, sessions, "", country)
		if err != nil {
			log.Printf("[web] create %d proxies for %s (%s): %v", count, keyID, country, err)
			return
		}
		if sk := a.state.getKey(keyID); sk != nil {
			sk.PlanCount += len(ps)
			sk.PlanSessions = sessions
			sk.PlanCountries = appendPlanCountries(sk.PlanCountries, country, len(ps))
			a.save()
		}
	}()
}

// appendPlanCountries records n new proxies in the country plan.
func appendPlanCountries(plan []PlanCountry, country string, n int) []PlanCountry {
	for i := range plan {
		if plan[i].Code == country {
			plan[i].Count += n
			return plan
		}
	}
	return append(plan, PlanCountry{Code: country, Count: n})
}

// consumePlanCountry removes n proxies from the country plan.
func consumePlanCountry(plan []PlanCountry, country string, n int) []PlanCountry {
	for i := range plan {
		if plan[i].Code == country {
			plan[i].Count -= n
			if plan[i].Count <= 0 {
				return append(plan[:i], plan[i+1:]...)
			}
			return plan
		}
	}
	return plan
}

// countries lists every country the active token can create proxies in.
func (a *poolApp) countries(w http.ResponseWriter, r *http.Request) {
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
	if tok == "" && len(a.state.Keys) > 0 {
		tok = a.state.Keys[0].Token
	}
	if tok == "" {
		writeErr(w, http.StatusBadRequest, errString("add a key first"))
		return
	}
	list, err := CountryDiscovery(tok)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"countries": list, "count": len(list)})
}

func (a *poolApp) deleteProxy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/proxies/")
	id = strings.TrimSuffix(id, "/")
	// allow a rotate/verify suffix
	if strings.HasSuffix(id, "/rotate") {
		id = strings.TrimSuffix(id, "/rotate")
		if err := a.mgr.RotateProxy(id); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "rotated": "true"})
		return
	}
	if strings.HasSuffix(id, "/verify") {
		id = strings.TrimSuffix(id, "/verify")
		ip, err := a.mgr.Verify(id)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "exit_ip": ip})
		return
	}
	if id == "" {
		writeErr(w, http.StatusNotFound, errString("not found"))
		return
	}
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
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// bulkDeleteProxies removes a set of proxies in one call.
func (a *poolApp) bulkDeleteProxies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(body.IDs) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": 0})
		return
	}
	deleted, byKey, byKeyCountry := a.deleteProxies(body.IDs)
	a.adjustPlans(byKey, byKeyCountry)
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

// deleteProxies removes ids and reports how many were deleted per key/country.
func (a *poolApp) deleteProxies(ids []string) (int, map[string]int, map[string]map[string]int) {
	deleted := 0
	byKey := map[string]int{}
	byKeyCountry := map[string]map[string]int{}
	for _, id := range ids {
		p, err := a.mgr.Status(id)
		if err != nil {
			continue
		}
		if err := a.mgr.DeleteProxy(id); err != nil {
			continue
		}
		byKey[p.KeyID]++
		if byKeyCountry[p.KeyID] == nil {
			byKeyCountry[p.KeyID] = map[string]int{}
		}
		byKeyCountry[p.KeyID][p.Country]++
		deleted++
	}
	return deleted, byKey, byKeyCountry
}

// adjustPlans keeps each key's replay plan in sync after deletions.
func (a *poolApp) adjustPlans(byKey map[string]int, byKeyCountry map[string]map[string]int) {
	if len(byKey) == 0 {
		return
	}
	for keyID, n := range byKey {
		if sk := a.state.getKey(keyID); sk != nil {
			for code, cn := range byKeyCountry[keyID] {
				if len(sk.PlanCountries) > 0 {
					sk.PlanCountries = consumePlanCountry(sk.PlanCountries, code, cn)
				}
			}
			if sk.PlanCount > 0 {
				sk.PlanCount -= n
				if sk.PlanCount < 0 {
					sk.PlanCount = 0
				}
			}
		}
	}
	a.save()
}

// settingsBody is the patch shape accepted by both the dashboard and /api/v1.
// Pointer fields so omitted values are never clobbered (0/"" are valid).
type settingsBody struct {
	PortBase   *int    `json:"port_base"`
	HTTPOffset *int    `json:"http_offset"`
	Sessions   *int    `json:"sessions"`
	ProbeURL   *string `json:"probe_url"`
	TokenFile  *string `json:"token_file"`
	ListenHost *string `json:"listen_host"`
	ProxyUser  *string `json:"proxy_user"`
	ProxyPass  *string `json:"proxy_pass"`
}

func (a *poolApp) saveSettings(w http.ResponseWriter, r *http.Request) {
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
}

// applySettings patches the runtime settings and reports whether already-running
// proxies need a rebuild to pick them up.
func (a *poolApp) applySettings(body settingsBody) (bool, error) {
	st := &a.state.Settings
	if body.PortBase != nil && *body.PortBase > 0 {
		st.PortBase = *body.PortBase
	}
	if body.HTTPOffset != nil {
		st.HTTPOffset = *body.HTTPOffset
	}
	if body.Sessions != nil && *body.Sessions > 0 {
		st.Sessions = *body.Sessions
	}
	if body.ProbeURL != nil && *body.ProbeURL != "" {
		st.ProbeURL = *body.ProbeURL
	}
	if body.TokenFile != nil && *body.TokenFile != st.TokenFile {
		st.TokenFile = *body.TokenFile
		a.applyTokenFile()
	}
	if body.ListenHost != nil {
		h := strings.TrimSpace(*body.ListenHost)
		if h == "" {
			h = "127.0.0.1"
		}
		if h != "127.0.0.1" && h != "0.0.0.0" {
			return false, errString("listen_host must be 127.0.0.1 or 0.0.0.0")
		}
		st.ListenHost = h
	}
	if body.ProxyUser != nil {
		st.ProxyUser = strings.TrimSpace(*body.ProxyUser)
	}
	if body.ProxyPass != nil {
		st.ProxyPass = *body.ProxyPass
	}
	// Proxies bind their listeners at creation, so a changed host/auth is only
	// picked up by proxies created afterwards. Report that to the caller.
	applyToExisting := (body.ListenHost != nil && *body.ListenHost != "" && *body.ListenHost != a.mgr.ListenHost()) ||
		(body.ProxyUser != nil && st.ProxyUser != a.mgr.Auth().User) ||
		(body.ProxyPass != nil && st.ProxyPass != a.mgr.Auth().Pass)
	a.mgr.SetPortBase(st.PortBase, st.HTTPOffset)
	a.mgr.SetProbeURL(st.ProbeURL)
	a.mgr.SetListenHost(st.ListenHost)
	a.mgr.SetAuth(st.ProxyUser, st.ProxyPass)
	a.save()
	return applyToExisting, nil
}

// applyTokenFile (re)starts the watched JWT feed.
func (a *poolApp) applyTokenFile() {
	if a.tokenStop != nil {
		a.tokenStop()
		a.tokenStop = nil
	}
	if a.tokenFile != "" {
		a.tokenStop = startTokenFeed(a.mgr, a.tokenFile)
		log.Printf("[web] watching token file %s", a.tokenFile)
	}
}

// ------------------------------------------------------------ routing

func (a *poolApp) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/logout", a.auth(a.logout))
	mux.HandleFunc("/api/me", a.me)

	mux.HandleFunc("/api/overview", a.auth(a.overview))
	mux.HandleFunc("/api/geo/refresh", a.auth(a.refreshGeo))            // POST
	mux.HandleFunc("/api/proxies/rebuild", a.auth(a.rebuildProxies))    // POST
	mux.HandleFunc("/api/countries", a.auth(a.countries))               // GET
	mux.HandleFunc("/api/keys", a.auth(a.addKey))                       // POST
	mux.HandleFunc("/api/keys/import", a.auth(a.importKey))             // POST (Windows)
	mux.HandleFunc("/api/keys/", a.auth(a.keyItem))
	mux.HandleFunc("/api/proxies", a.auth(a.createProxies))             // POST
	mux.HandleFunc("/api/proxies/bulk-delete", a.auth(a.bulkDeleteProxies)) // POST
	mux.HandleFunc("/api/proxies/", a.auth(a.deleteProxy))
	mux.HandleFunc("/api/settings", a.auth(a.saveSettings))  // POST

	// One-click proxy list export (text file or JSON) — see export.go.
	mux.HandleFunc("/api/export", a.auth(a.exportProxies)) // GET

	// API keys managed from the dashboard (cookie session).
	mux.HandleFunc("/api/apikeys", a.auth(a.apiKeys))     // GET list / POST create
	mux.HandleFunc("/api/apikeys/", a.auth(a.apiKeyItem)) // DELETE

	// External JSON API (bearer API key, see apiv1.go).
	mux.HandleFunc("/api/v1/", a.apiV1)
	mux.HandleFunc("/api/v1", a.apiV1)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r)
	})
	return mux
}

func (a *poolApp) keyItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	rest = strings.TrimSuffix(rest, "/")
	if rest == "import" {
		a.importKey(w, r)
		return
	}
	if strings.HasSuffix(rest, "/token") {
		a.setKeyToken(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		a.deleteKey(w, r)
		return
	}
	writeErr(w, http.StatusMethodNotAllowed, errString("method not allowed"))
}

// ------------------------------------------------------------ helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type apiErr struct{ Error string `json:"error"` }

func errString(s string) error { return fmt.Errorf("%s", s) }

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, apiErr{Error: err.Error()})
}
