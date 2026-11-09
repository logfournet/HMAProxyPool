package main

// Standalone HMA session minting — no HMA client, no driver, no admin.
//
// Reverse-engineered protocol:
//   discovery : GET https://api.se-platform.com/discovery/v9/discover  (Bearer JWT)
//   wrangler  : UDP <server_ip>:8080
//               [24B nonce][32B client x25519 pub][2B BE len][nacl box payload]
//               req  = {"ac":1,"at":"<JWT>","cores":<n>}
//               resp = {"sc":200,"ctip":"100.x.y.z/32","cdns":"...",
//                       "wgps":[51820],"add_peers":[{"pub_key":..,"port":..}],"ttl":240}
// The server assigns each session exactly one working peer (randomly), so the
// client must probe all 4 peers and pick the live one.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	sePlatform  = "https://api.se-platform.com/discovery/v9/discover"
	seClientKey = "DECE424681E71043331A3DB13CB0905E03EB605478F1584055ED0EECE80A3E01"
	seTenant    = "3bfdc5ab-a90f-4503-8349-34d0991d33a3"
	defaultTTL  = 240
)

// HMAServer is one discovery entry.
type HMAServer struct {
	IP     string
	PubKey string // base64 x25519 public key
	Port   int    // wrangler UDP port (8080)
}

// MintedSession is the material needed to bring up a WireGuard tunnel.
type MintedSession struct {
	PrivKey  []byte // raw x25519 private key
	Ctip     string // "100.120.x.y/32"
	CDNS     string
	Peers    []PeerConfig // the 4 candidate peers (base + add_peers)
	TTL      int          // seconds
	MintedAt time.Time
}

func (m *MintedSession) age() time.Duration { return time.Since(m.MintedAt) }

// ------------- discovery -------------

type discoveryResp struct {
	Data struct {
		IPs []struct {
			IP        string       `json:"ip"`
			Protocol  string       `json:"protocol"`
			Geo       discoveryGeo `json:"geo"`
			Wireguard *struct {
				PublicKey     string `json:"public_key"`
				WranglerPorts []int  `json:"wrangler_ports"`
			} `json:"wireguard"`
		} `json:"ips"`
	} `json:"data"`
}

// discoveryGeo is the location block discovery attaches to every server.
type discoveryGeo struct {
	CountryCode string  `json:"country_code"`
	StateCode   string  `json:"state_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	LocationKey string  `json:"location_key"`
}

// applyDiscoveryHeaders sets the client identity HMA's discovery requires.
func applyDiscoveryHeaders(req *http.Request, jwt string) {
	h := req.Header
	h.Set("Authorization", "Bearer "+jwt)
	h.Set("SE-Client-Type", "hma101")
	h.Set("SE-Client-API-Key", seClientKey)
	h.Set("SE-Client-Name", "GVPN")
	h.Set("SE-Client-Version", "26.10.12427")
	h.Set("X-NLok-Tenant-ID", seTenant)
	h.Set("Accept", "application/json")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("User-Agent", "GVPN")
}

// serversFrom turns a parsed discovery body into the server list.
func serversFrom(dr discoveryResp) []HMAServer {
	out := make([]HMAServer, 0, len(dr.Data.IPs))
	for _, ip := range dr.Data.IPs {
		if ip.Protocol != "wireguard" || ip.Wireguard == nil || ip.Wireguard.PublicKey == "" {
			continue
		}
		port := 8080
		if len(ip.Wireguard.WranglerPorts) > 0 {
			port = ip.Wireguard.WranglerPorts[0]
		}
		out = append(out, HMAServer{IP: ip.IP, PubKey: ip.Wireguard.PublicKey, Port: port})
	}
	return out
}

// parseDiscovery validates a raw discovery body and extracts its servers.
func parseDiscovery(body []byte) ([]HMAServer, error) {
	var dr discoveryResp
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, fmt.Errorf("discovery parse: %w", err)
	}
	out := serversFrom(dr)
	if len(out) == 0 {
		return nil, fmt.Errorf("discovery returned no wireguard servers")
	}
	return out, nil
}

// Discovery returns the current WireGuard server list for a JWT.
func Discovery(jwt string) ([]HMAServer, error) {
	req, err := http.NewRequest("GET", sePlatform, nil)
	if err != nil {
		return nil, err
	}
	applyDiscoveryHeaders(req, jwt)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("discovery: HTTP %d: %s", resp.StatusCode, short(body))
	}
	return parseDiscovery(body)
}

// ------------- wrangler mint -------------

type mintRequest struct {
	Ac    int    `json:"ac"`
	At    string `json:"at"`
	Cores int    `json:"cores"`
}

type mintResponse struct {
	Sc       int    `json:"sc"`
	St       string `json:"st"`
	Ctip     string `json:"ctip"`
	Cdns     string `json:"cdns"`
	Wgps     []int  `json:"wgps"`
	AddPeers []struct {
		PubKey string `json:"pub_key"`
		Port   int    `json:"port"`
	} `json:"add_peers"`
	TTL int `json:"ttl"`
}

// MintSession asks the Wrangler (UDP 8080) for a fresh session. The server
// accepts any freshly generated X25519 keypair — no HMA client involved.
func MintSession(srv HMAServer, jwt string, timeout time.Duration) (*MintedSession, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serverKey, err := base64.StdEncoding.DecodeString(srv.PubKey)
	if err != nil || len(serverKey) != 32 {
		return nil, fmt.Errorf("bad server public key: %v", err)
	}
	var sk [32]byte
	copy(sk[:], serverKey)
	var shared [32]byte
	box.Precompute(&shared, &sk, priv)

	payload, _ := json.Marshal(mintRequest{Ac: 1, At: jwt, Cores: 12})
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	boxed := box.SealAfterPrecomputation(nil, payload, &nonce, &shared)

	msg := make([]byte, 0, 24+32+2+len(boxed))
	msg = append(msg, nonce[:]...)
	msg = append(msg, pub[:]...)
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(boxed)))
	msg = append(msg, ln[:]...)
	msg = append(msg, boxed...)

	conn, err := net.DialTimeout("udp", net.JoinHostPort(srv.IP, fmt.Sprint(srv.Port)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("wrangler recv: %w", err)
	}
	data := buf[:n]
	if len(data) < 58 {
		return nil, fmt.Errorf("wrangler: short response %d", len(data))
	}
	bl := int(binary.BigEndian.Uint16(data[56:58]))
	if 58+bl > len(data) {
		return nil, fmt.Errorf("wrangler: bad body len %d > %d", bl, len(data)-58)
	}
	var rnonce [24]byte
	copy(rnonce[:], data[:24])
	plain, ok := box.OpenAfterPrecomputation(nil, data[58:58+bl], &rnonce, &shared)
	if !ok {
		return nil, fmt.Errorf("wrangler: box open failed")
	}
	var mr mintResponse
	if err := json.Unmarshal(plain, &mr); err != nil {
		return nil, fmt.Errorf("wrangler parse: %w", err)
	}
	if mr.Sc != 200 || mr.Ctip == "" {
		return nil, fmt.Errorf("wrangler: sc=%d st=%q", mr.Sc, mr.St)
	}

	m := &MintedSession{
		PrivKey:  []byte(priv[:]),
		Ctip:     mr.Ctip,
		CDNS:     mr.Cdns,
		TTL:      mr.TTL,
		MintedAt: time.Now(),
	}
	if m.TTL <= 0 {
		m.TTL = defaultTTL
	}
	if m.CDNS == "" {
		m.CDNS = "100.123.0.1"
	}

	allowed := []string{"0.0.0.0/1", "128.0.0.0/1"}

	// base peer (from discovery, port wgps[0]) + add_peers
	addPeer := func(pubB64 string, port int) PeerConfig {
		raw, _ := base64.StdEncoding.DecodeString(pubB64)
		return PeerConfig{
			PublicKey:  hex.EncodeToString(raw),
			Endpoint:   net.JoinHostPort(srv.IP, fmt.Sprint(port)),
			AllowedIPs: allowed,
			Keepalive:  25,
		}
	}
	if len(mr.Wgps) > 0 {
		m.Peers = append(m.Peers, addPeer(srv.PubKey, mr.Wgps[0]))
	}
	for _, p := range mr.AddPeers {
		m.Peers = append(m.Peers, addPeer(p.PubKey, p.Port))
	}
	if len(m.Peers) == 0 {
		return nil, fmt.Errorf("wrangler: no peers in response")
	}
	return m, nil
}

func short(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 160 {
		b = b[:160]
	}
	return string(b)
}
