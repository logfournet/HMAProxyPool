// mkconfig turns a captured wireguardtun.exe command line plus the
// auth.wireguard private key into a tunnels.json for hgproxy.
//
// usage: mkconfig <cmdline.txt> <auth.wireguard> <out.json> [base_port] [mtu]
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type peerCfg struct {
	PublicKey   string   `json:"public_key"`
	Endpoint    string   `json:"endpoint"`
	AllowedIPs  []string `json:"allowed_ips"`
	Keepalive   int      `json:"persistent_keepalive"`
}

type tunnelCfg struct {
	Name        string   `json:"name"`
	Port        int      `json:"port"`
	HTTPPort    int      `json:"http_port,omitempty"`
	PrivateKey  string   `json:"private_key"`
	Addresses   []string `json:"addresses"`
	DNS         []string `json:"dns"`
	MTU         int      `json:"mtu"`
	Peer        peerCfg  `json:"peer"`
}

type topCfg struct {
	ListenHost string      `json:"listen_host"`
	PortBase   int         `json:"port_base"`
	HTTPOffset int         `json:"http_offset"`
	VerifyURL  string      `json:"verify_url"`
	Tunnels    []tunnelCfg `json:"tunnels"`
}

var (
	rePeer = regexp.MustCompile(`-peer\s+"([^"]+)"`)
	reAddr = regexp.MustCompile(`-iface_addr\s+([0-9./]+)`)
	reKA   = regexp.MustCompile(`-persistent_keepalive\s+(\d+)`)
)

func toHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: mkconfig <cmdline.txt> <auth.wireguard> <out.json> [base_port] [mtu]")
		os.Exit(2)
	}
	cmdlinePath, authPath, outPath := os.Args[1], os.Args[2], os.Args[3]
	basePort, mtu := 3000, 1420
	if len(os.Args) > 4 {
		if v, err := strconv.Atoi(os.Args[4]); err == nil {
			basePort = v
		}
	}
	if len(os.Args) > 5 {
		if v, err := strconv.Atoi(os.Args[5]); err == nil {
			mtu = v
		}
	}

	cmdRaw, err := os.ReadFile(cmdlinePath)
	if err != nil {
		panic(err)
	}
	authRaw, err := os.ReadFile(authPath)
	if err != nil {
		panic(err)
	}
	cmdline := string(cmdRaw)

	privHex, err := toHex(strings.TrimSpace(string(authRaw)))
	if err != nil {
		panic("private key: " + err.Error())
	}

	var addresses []string
	if m := reAddr.FindStringSubmatch(cmdline); m != nil {
		addresses = []string{m[1]}
	} else {
		panic("no -iface_addr in command line")
	}

	keepalive := 25
	if m := reKA.FindStringSubmatch(cmdline); m != nil {
		keepalive, _ = strconv.Atoi(m[1])
	}

	cfg := topCfg{
		ListenHost: "127.0.0.1",
		PortBase:   basePort,
		HTTPOffset: 1000,
		VerifyURL:  "https://icanhazip.com/",
	}

	peers := rePeer.FindAllStringSubmatch(cmdline, -1)
	if len(peers) == 0 {
		panic("no -peer entries in command line")
	}
	for i, m := range peers {
		// ip|port|pubkey|cidr, cidr, ...
		parts := strings.SplitN(m[1], "|", 4)
		if len(parts) < 3 {
			panic("bad peer spec: " + m[1])
		}
		ip, port, pubB64 := parts[0], parts[1], parts[2]
		var allowed []string
		if len(parts) == 4 {
			for _, c := range strings.Split(parts[3], ",") {
				c = strings.TrimSpace(c)
				if c != "" {
					allowed = append(allowed, c)
				}
			}
		}
		pubHex, err := toHex(pubB64)
		if err != nil {
			panic("peer key " + pubB64 + ": " + err.Error())
		}
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		cfg.Tunnels = append(cfg.Tunnels, tunnelCfg{
			Name:       fmt.Sprintf("%s-%s", ip, port),
			Port:       basePort + i,
			HTTPPort:   basePort + i + 1000,
			PrivateKey: privHex,
			Addresses:  addresses,
			DNS:        []string{"1.1.1.1", "8.8.8.8"},
			MTU:        mtu,
			Peer: peerCfg{
				PublicKey:  pubHex,
				Endpoint:   ip + ":" + port,
				AllowedIPs: allowed,
				Keepalive:  keepalive,
			},
		})
	}

	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s: %d tunnel(s), iface %s, key %s...\n", outPath, len(cfg.Tunnels), addresses[0], privHex[:8])
	for _, t := range cfg.Tunnels {
		fmt.Printf("  %-24s port %d/%d  peer %s\n", t.Name, t.Port, t.HTTPPort, t.Peer.Endpoint)
	}
}