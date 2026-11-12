package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/things-go/go-socks5"
)

// ProxyAuth is the shared credential every proxy listener in the pool uses.
type ProxyAuth struct {
	User string
	Pass string
}

// enabled reports whether clients must authenticate.
func (a ProxyAuth) enabled() bool { return a.User != "" }

// StartSocks5 serves a SOCKS5 proxy on listen, routing every connection
// through t. A non-empty auth requires RFC 1929 username/password auth.
func StartSocks5(listen string, t *Tunnel, auth ProxyAuth) (net.Listener, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	opts := []socks5.Option{
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return t.DialContext(dctx, network, addr)
		}),
		socks5.WithLogger(socks5.NewLogger(log.New(io.Discard, "", 0))),
	}
	if auth.enabled() {
		opts = append(opts, socks5.WithCredential(
			socks5.StaticCredentials{auth.User: auth.Pass}))
	}
	srv := socks5.NewServer(opts...)
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("[%s] socks5 %s stopped: %v", t.Name, listen, err)
		}
	}()
	return ln, nil
}

// StartHTTPProxy serves an HTTP proxy (CONNECT + absolute-URI) on listen,
// routing every connection through t. A non-empty auth requires HTTP Basic.
func StartHTTPProxy(listen string, t *Tunnel, auth ProxyAuth) (net.Listener, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHTTPProxyConn(c, t, auth)
		}
	}()
	return ln, nil
}

func serveHTTPProxyConn(c net.Conn, t *Tunnel, auth ProxyAuth) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if auth.enabled() {
		u, p, ok := proxyBasicAuth(req)
		if !ok || u != auth.User || p != auth.Pass {
			_, _ = io.WriteString(c,
				"HTTP/1.1 407 Proxy Authentication Required\r\n"+
					"Proxy-Authenticate: Basic realm=\"HMAProxyPool\"\r\n"+
					"Content-Length: 0\r\n\r\n")
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if req.Method == http.MethodConnect {
		target := req.Host
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		up, err := t.DialContext(ctx, "tcp", target)
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer up.Close()
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		pipe(c, up)
		return
	}

	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	up, err := t.DialContext(ctx, "tcp", req.URL.Host)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})

	if err := req.Write(up); err != nil {
		return
	}
	pipe(c, up)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); closeWrite(a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); closeWrite(b); done <- struct{}{} }()
	<-done
	<-done
}

// proxyBasicAuth returns the credentials from Proxy-Authorization, falling back
// to Authorization. net/http's Request.BasicAuth only looks at Authorization,
// which is the wrong header for a proxy (curl and browsers send
// Proxy-Authorization), so a proxy that used it would reject every client.
func proxyBasicAuth(req *http.Request) (user, pass string, ok bool) {
	h := req.Header.Get("Proxy-Authorization")
	if h == "" {
		h = req.Header.Get("Authorization")
	}
	if h == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}



// httpClient is a thin wrapper so tunnel.go does not import net/http constants.
type httpClient struct {
	c *http.Client
}

func newHTTPClient(dial func(context.Context, string, string) (net.Conn, error), timeoutSec int) *httpClient {
	tr := &http.Transport{
		DialContext:           dial,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	if timeoutSec <= 0 {
		timeoutSec = 20
	}
	return &httpClient{c: &http.Client{Transport: tr, Timeout: time.Duration(timeoutSec) * time.Second}}
}

// GetExitIP dials verifyURL through the tunnel and returns the first
// whitespace-trimmed body (i.e. the public IP).
func (t *Tunnel) GetExitIP(ctx context.Context, verifyURL string) (string, error) {
	cl := t.HTTPClient(20)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := cl.c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(string(body))
	if out == "" {
		return "", fmt.Errorf("empty response from %s", verifyURL)
	}
	return out, nil
}