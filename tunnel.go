package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// member is one WireGuard peer instance inside a tunnel. A tunnel keeps one
// member per HMA peer (4 total) because the server routes traffic through only
// one of them at a time and rotates that choice — so we hedge at dial time.
type member struct {
	dev *device.Device
	net *netstack.Net
	bnd *countingBind
	cfg TunnelConfig
}

// Tunnel is one logical VPN exit exposed as one local proxy port. It may hold
// several WireGuard peers (members) that share the session's key/address.
type Tunnel struct {
	Name string
	cfg  TunnelConfig

	mu         sync.RWMutex
	members    []*member
	lastWinner int

	dials  atomic.Int64
	errs   atomic.Int64
	hedges atomic.Int64

	// Sup, when set, is the session supervisor that owns this tunnel (mint
	// mode). Stats() merges its liveness fields into /status output.
	Sup *Supervisor
}

// deviceLogLevel controls wireguard-go logging; -verbose raises it.
var deviceLogLevel = device.LogLevelError

const hedgeStagger = 50 * time.Millisecond

// StartTunnel brings up a single WireGuard peer and returns a dialer bound to it.
func StartTunnel(cfg TunnelConfig) (*Tunnel, error) {
	t := &Tunnel{Name: cfg.Name, cfg: cfg}
	if err := t.build([]TunnelConfig{cfg}); err != nil {
		return nil, err
	}
	return t, nil
}

// Replace atomically swaps this tunnel onto one configuration.
func (t *Tunnel) Replace(cfg TunnelConfig) error { return t.build([]TunnelConfig{cfg}) }

// ReplaceMany atomically swaps this tunnel onto a set of peer configurations
// (one member each). In-flight dials on the old members fail and are retried.
func (t *Tunnel) ReplaceMany(cfgs []TunnelConfig) error { return t.build(cfgs) }

func (t *Tunnel) build(cfgs []TunnelConfig) error {
	if len(cfgs) == 0 {
		return fmt.Errorf("no peers")
	}
	members := make([]*member, 0, len(cfgs))
	for _, cfg := range cfgs {
		m, err := newMember(cfg)
		if err != nil {
			for _, x := range members {
				x.close()
			}
			return err
		}
		members = append(members, m)
	}

	t.mu.Lock()
	old := t.members
	t.members = members
	t.cfg = cfgs[0]
	t.mu.Unlock()

	for _, x := range old {
		x.close()
	}
	return nil
}

func newMember(cfg TunnelConfig) (*member, error) {
	cb := &countingBind{Bind: conn.NewDefaultBind()}
	addrs := make([]netip.Addr, 0, len(cfg.Addresses))
	for _, a := range cfg.Addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", a, err)
		}
		addrs = append(addrs, p.Addr())
	}
	dns := make([]netip.Addr, 0, len(cfg.DNS))
	for _, d := range cfg.DNS {
		a, err := netip.ParseAddr(d)
		if err != nil {
			return nil, fmt.Errorf("dns %q: %w", d, err)
		}
		dns = append(dns, a)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	dev := device.NewDevice(tunDev, cb, device.NewLogger(deviceLogLevel, "wg["+cfg.Name+"] "))
	if err := dev.IpcSet(buildUAPI(cfg)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}
	return &member{dev: dev, net: tnet, bnd: cb, cfg: cfg}, nil
}

func (m *member) close() {
	if m.dev != nil {
		m.dev.Close()
		m.dev = nil
	}
}

func buildUAPI(cfg TunnelConfig) string {
	var b strings.Builder
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKey)
	fmt.Fprintf(&b, "public_key=%s\n", cfg.Peer.PublicKey)
	if cfg.Peer.PresharedKey != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", cfg.Peer.PresharedKey)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.Peer.Endpoint)
	for _, ip := range cfg.Peer.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
	}
	if cfg.Peer.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.Peer.Keepalive)
	}
	return b.String()
}

func (t *Tunnel) snapshot() []*member {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.members
}

// cand is one member plus its original index (used for sticky-winner tracking).
type cand struct {
	m    *member
	orig int
}

// DialContext routes a connection through whichever member answers first.
// Hostnames are resolved on the host (the tunnel's own resolver is unreliable)
// and forced to IPv4, because HMA only assigns an IPv4 interface address.
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialAddr, err := t.resolveIPv4(ctx, network, addr)
	if err != nil {
		t.errs.Add(1)
		log.Printf("[%s] resolve %s: %v", t.Name, addr, err)
		return nil, err
	}
	members := t.snapshot()
	if len(members) == 0 {
		t.errs.Add(1)
		return nil, fmt.Errorf("tunnel not ready")
	}
	if len(members) == 1 {
		c, err := members[0].net.DialContext(ctx, network, dialAddr)
		if err != nil {
			t.errs.Add(1)
			log.Printf("[%s] dial %s %s: %v", t.Name, network, dialAddr, err)
			return nil, err
		}
		t.dials.Add(1)
		return c, nil
	}

	// HMA routes each session through only one of its peers at any instant and
	// roams that choice, so a single hedge can still land in a dead window.
	// Prefer the peer that won last (the active one is usually stable for a
	// while), then retry the whole hedge a few times before giving up.
	// prefer the peer that won last
	cands := make([]cand, len(members))
	for i, m := range members {
		cands[i] = cand{m: m, orig: i}
	}
	t.mu.RLock()
	winner := t.lastWinner
	t.mu.RUnlock()
	if winner > 0 && winner < len(cands) {
		rot := make([]cand, 0, len(cands))
		rot = append(rot, cands[winner])
		for i, c := range cands {
			if i != winner {
				rot = append(rot, c)
			}
		}
		cands = rot
	}

	var lastErr error
	for pass := 0; pass < dialPasses; pass++ {
		if err := ctx.Err(); err != nil {
			break
		}
		pctx, pcancel := context.WithTimeout(ctx, dialPassTimeout[pass])
		c, err := t.raceDial(pctx, network, dialAddr, cands)
		pcancel()
		if err == nil {
			return c, nil
		}
		lastErr = err
		if pass+1 < dialPasses {
			select {
			case <-time.After(dialPassBackoff):
			case <-ctx.Done():
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no path")
	}
	// Ask the supervisor for a brand-new session in the background so the next
	// request does not keep hammering a session the server has stopped routing.
	if t.Sup != nil {
		t.Sup.requestRenew()
	}
	t.errs.Add(1)
	return nil, lastErr
}

// dialPassTimeout escalates: the first pass fails fast so a dead window is
// recycled quickly, later passes allow for slow paths.
var dialPassTimeout = [dialPasses]time.Duration{
	700 * time.Millisecond,
	1200 * time.Millisecond,
	1800 * time.Millisecond,
	2500 * time.Millisecond,
	3500 * time.Millisecond,
}

const (
	dialPasses      = 5
	dialPassBackoff = 60 * time.Millisecond
)

// raceDial starts the first candidate immediately and each subsequent one after
// a small stagger, returning the first successful connection. Losers are
// cancelled and any late successful connection is closed.
func (t *Tunnel) raceDial(ctx context.Context, network, addr string, cands []cand) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
		idx int
	}
	ch := make(chan res, len(cands))
	dctx, cancel := context.WithCancel(ctx)

	for i, cd := range cands {
		go func(i int, cd cand) {
			if i > 0 {
				timer := time.NewTimer(time.Duration(i) * hedgeStagger)
				select {
				case <-timer.C:
				case <-dctx.Done():
					timer.Stop()
					ch <- res{err: dctx.Err(), idx: cd.orig}
					return
				}
			}
			c, err := cd.m.net.DialContext(dctx, network, addr)
			ch <- res{c: c, err: err, idx: cd.orig}
		}(i, cd)
	}

	var firstErr error
	for i := 0; i < len(cands); i++ {
		r := <-ch
		if r.err == nil && r.c != nil {
			t.dials.Add(1)
			t.mu.Lock()
			t.lastWinner = r.idx
			t.mu.Unlock()
			if i > 0 {
				t.hedges.Add(1)
			}
			cancel()
			go func(remaining int) {
				for k := 0; k < remaining; k++ {
					rr := <-ch
					if rr.c != nil {
						_ = rr.c.Close()
					}
				}
			}(len(cands) - i - 1)
			return r.c, nil
		}
		if firstErr == nil && r.err != nil && r.err != context.Canceled {
			firstErr = r.err
		}
	}
	cancel()
	if firstErr == nil {
		firstErr = fmt.Errorf("all %d paths failed", len(cands))
	}
	return nil, firstErr
}

// Probe opens a TCP connection through the tunnel and immediately closes it.
// A successful connect proves at least one member path is live.
func (t *Tunnel) Probe(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	c, err := t.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

func (t *Tunnel) resolveIPv4(ctx context.Context, network, addr string) (string, error) {
	if network != "tcp" && network != "udp" {
		return addr, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, nil // let the stack produce the error
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("%s is IPv6; tunnel has no IPv6 address", host)
		}
		return addr, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), port), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %s", host)
}

func (t *Tunnel) netStack() *netstack.Net {
	members := t.snapshot()
	if len(members) == 0 {
		return nil
	}
	return members[0].net
}

// HTTPClient returns a client whose traffic leaves through this tunnel.
func (t *Tunnel) HTTPClient(timeoutSec int) *httpClient {
	return newHTTPClient(t.DialContext, timeoutSec)
}

// Stats reports counters aggregated across all members.
func (t *Tunnel) Stats() TunnelStats {
	members := t.snapshot()
	s := TunnelStats{Name: t.Name, Port: t.cfg.Port, Dials: t.dials.Load(), Errors: t.errs.Load(), Hedges: t.hedges.Load()}
	t.mu.RLock()
	s.PeerIdx = t.lastWinner
	t.mu.RUnlock()
	for _, m := range members {
		if m.dev == nil {
			continue
		}
		raw, err := m.dev.IpcGet()
		if err == nil {
			for _, line := range strings.Split(raw, "\n") {
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				switch k {
				case "rx_bytes":
					n, _ := strconv.ParseInt(v, 10, 64)
					s.RxBytes += n
				case "tx_bytes":
					n, _ := strconv.ParseInt(v, 10, 64)
					s.TxBytes += n
				case "last_handshake_time_sec":
					n, _ := strconv.ParseInt(v, 10, 64)
					if n > s.LastHandshake {
						s.LastHandshake = n
					}
				case "listen_port":
					if s.LocalPort == 0 {
						s.LocalPort, _ = strconv.Atoi(v)
					}
				}
			}
		}
		if m.bnd != nil {
			s.RawTX += m.bnd.RawTX()
			s.RawRX += m.bnd.RawRX()
		}
	}
	if t.Sup != nil {
		peerIdx, age, remints, swaps, lastErr, _ := t.Sup.status()
		if t.lastWinner == 0 {
			s.PeerIdx = peerIdx
		}
		s.SessionAge = int(age.Seconds())
		s.Remints = remints
		s.PeerSwaps = swaps
		s.LastError = lastErr
		if m := t.Sup.currentSession(); m != nil {
			s.SessionCtip = m.Ctip
		}
	}
	return s
}

func (t *Tunnel) Close() {
	t.mu.Lock()
	old := t.members
	t.members = nil
	t.mu.Unlock()
	for _, m := range old {
		m.close()
	}
}

// RawState returns the raw WireGuard UAPI state (debugging).
func (t *Tunnel) RawState() string {
	var b strings.Builder
	for i, m := range t.snapshot() {
		if m.dev == nil {
			continue
		}
		fmt.Fprintf(&b, "--- member %d (%s)\n", i, m.cfg.Peer.Endpoint)
		if raw, err := m.dev.IpcGet(); err == nil {
			b.WriteString(raw)
		} else {
			fmt.Fprintf(&b, "IpcGet error: %v\n", err)
		}
	}
	return b.String()
}

// TunnelStats is the JSON shape served by /status.
type TunnelStats struct {
	Name          string `json:"name"`
	Port          int    `json:"port"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	LastHandshake int64  `json:"last_handshake_unix"`
	Dials         int64  `json:"dials"`
	Errors        int64  `json:"errors"`
	Hedges        int64  `json:"hedges"`
	RawTX         int64  `json:"raw_tx_packets"`
	RawRX         int64  `json:"raw_rx_packets"`
	LocalPort     int    `json:"local_udp_port"`
	ExitIP        string `json:"exit_ip,omitempty"`
	Up            bool   `json:"up"`

	// supervisor / mint-mode liveness
	PeerIdx     int    `json:"peer_idx"`
	SessionAge  int    `json:"session_age_sec,omitempty"`
	SessionCtip string `json:"session_ctip,omitempty"`
	Remints     int64  `json:"remints,omitempty"`
	PeerSwaps   int64  `json:"peer_swaps,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}
