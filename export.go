package main

// Proxy list export for the dashboard: one click to get every endpoint as a
// copy-paste block or a file.
//
//	GET /api/export?format=http|socks5|json&host=1.2.3.4&state=up&country=VN
//
// Why this exists: the pool binds to 0.0.0.0 (or 127.0.0.1) so the raw
// Socks5/HTTP fields in the API are unusable from another machine — a client
// needs the address it can actually reach. The export rewrites the host part to
// whatever the browser reached the dashboard on (or an explicit ?host=), so the
// output is immediately usable.

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// exportFormats maps a requested format to the URL scheme it emits.
var exportFormats = map[string]string{
	"http":   "http",
	"socks5": "socks5",
	"socks":  "socks5",
	"https":  "http", // HTTP proxies carry https via CONNECT
}

// endpointHost decides which host to put in front of every proxy port.
// Order: explicit ?host=, then X-Forwarded-Host / Host from the browser, then
// the listener bind address when it is a concrete IP.
func (a *poolApp) endpointHost(r *http.Request) string {
	if h := strings.TrimSpace(r.URL.Query().Get("host")); h != "" {
		return stripPort(h)
	}
	if h := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); h != "" {
		return stripPort(strings.Split(h, ",")[0])
	}
	if h := strings.TrimSpace(r.Host); h != "" && !isLoopbackHost(stripPort(h)) {
		return stripPort(h)
	}
	if h := a.mgr.ListenHost(); h == "0.0.0.0" {
		return "127.0.0.1"
	} else if h != "" {
		return h
	}
	return "127.0.0.1"
}

// stripPort removes :port and IPv6 brackets from a host[:port] pair.
func stripPort(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

// isLoopbackHost reports whether h is a loopback or unspecified address.
func isLoopbackHost(h string) bool {
	if h == "" || h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// proxyLine renders one proxy as scheme://[user:pass@]host:port.
func proxyLine(scheme, host string, port int, user, pass string) string {
	if port <= 0 {
		return ""
	}
	hp := net.JoinHostPort(host, strconv.Itoa(port))
	if user != "" {
		return fmt.Sprintf("%s://%s:%s@%s", scheme, user, pass, hp)
	}
	return scheme + "://" + hp
}

// exportProxies answers GET /api/export (cookie session auth).
func (a *poolApp) exportProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeErr(w, http.StatusMethodNotAllowed, errString("GET only"))
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "socks5"
	}
	scheme, known := exportFormats[format]
	if !known && format != "json" {
		writeErr(w, http.StatusBadRequest,
			errString("format must be http, socks5 or json"))
		return
	}
	if format == "json" {
		scheme = "socks5" // json reports both ports; scheme only labels the row URL
	}

	host := a.endpointHost(r)
	user, pass := a.mgr.Auth().User, a.mgr.Auth().Pass

	state := strings.ToLower(r.URL.Query().Get("state"))
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	onlyWorking := r.URL.Query().Get("working") == "1"

	views := a.proxyViews()
	lines := make([]string, 0, len(views))
	type row struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Country string `json:"country,omitempty"`
		ExitIP  string `json:"exit_ip,omitempty"`
		State   string `json:"state"`
		Up      bool   `json:"up"`
		Socks5  string `json:"socks5"`
		HTTP    string `json:"http,omitempty"`
		URL     string `json:"url,omitempty"`
	}
	rows := make([]row, 0, len(views))

	for _, v := range views {
		if onlyWorking && !v.Up {
			continue
		}
		if state != "" && !matchesState(v.ProxyStatus, state) {
			continue
		}
		cc := strings.ToUpper(v.CountryCode)
		if cc == "" {
			cc = strings.ToUpper(v.ProxyStatus.Country)
		}
		if country != "" && cc != country && strings.ToUpper(v.Country) != country {
			continue
		}

		socks := proxyLine("socks5", host, v.Port, user, pass)
		httpURL := proxyLine("http", host, v.HTTPPort, user, pass)

		if format == "json" {
			rows = append(rows, row{
				ID: v.ID, Name: v.Name, Country: v.Country, ExitIP: v.ExitIP,
				State: v.State, Up: v.Up, Socks5: socks, HTTP: httpURL,
			})
			continue
		}

		line := socks
		if scheme == "http" {
			line = httpURL
		}
		if line == "" {
			continue
		}
		lines = append(lines, line)
		rows = append(rows, row{
			ID: v.ID, Name: v.Name, Country: v.Country, ExitIP: v.ExitIP,
			State: v.State, Up: v.Up, URL: line,
		})
	}

	if format == "json" {
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   len(rows),
			"host":    host,
			"proxies": rows,
		})
		return
	}

	txt := strings.Join(lines, "\n")
	if txt != "" {
		txt += "\n"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%s-proxies.txt", scheme))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(txt))
	}
}

// matchesState compares the request's state filter with a proxy status.
func matchesState(p *ProxyStatus, want string) bool {
	switch want {
	case "up":
		return p.Up
	case "down":
		return !p.Up
	default:
		return strings.EqualFold(p.State, want)
	}
}
