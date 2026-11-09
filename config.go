package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Config is the whole runtime description of the multiplexer.
type Config struct {
	// ListenHost is the address every local proxy binds to. Default 127.0.0.1.
	ListenHost string `json:"listen_host"`
	// PortBase is used when a tunnel does not declare an explicit port.
	PortBase int `json:"port_base"`
	// HTTPOffset is added to the tunnel port to derive the HTTP CONNECT port.
	// Set to 0 to disable HTTP listeners entirely.
	HTTPOffset int `json:"http_offset"`
	// VerifyURL is dialed through every tunnel by -verify and by /status.
	VerifyURL string `json:"verify_url"`

	Tunnels []TunnelConfig `json:"tunnels"`
}

// TunnelConfig describes one WireGuard exit.
type TunnelConfig struct {
	Name       string     `json:"name"`
	Port       int        `json:"port,omitempty"`
	HTTPPort   int        `json:"http_port,omitempty"`
	PrivateKey string     `json:"private_key"`
	Addresses  []string   `json:"addresses"` // local tunnel addresses, e.g. 10.14.0.2/32
	DNS        []string   `json:"dns"`
	MTU        int        `json:"mtu,omitempty"`
	Peer       PeerConfig `json:"peer"`
}

// PeerConfig is the remote side of a WireGuard tunnel.
type PeerConfig struct {
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"persistent_keepalive,omitempty"`
}

// LoadConfig reads and normalises a tunnels.json file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) // tolerate Windows UTF-8 BOM
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.normalise()
	if len(cfg.Tunnels) == 0 {
		return nil, fmt.Errorf("%s: no tunnels defined", path)
	}
	for i, t := range cfg.Tunnels {
		if t.Name == "" {
			return nil, fmt.Errorf("tunnels[%d]: name is required", i)
		}
		if t.PrivateKey == "" {
			return nil, fmt.Errorf("tunnel %q: private_key is required", t.Name)
		}
		if t.Peer.PublicKey == "" {
			return nil, fmt.Errorf("tunnel %q: peer.public_key is required", t.Name)
		}
		if t.Peer.Endpoint == "" {
			return nil, fmt.Errorf("tunnel %q: peer.endpoint is required", t.Name)
		}
		if len(t.Addresses) == 0 {
			return nil, fmt.Errorf("tunnel %q: addresses is required", t.Name)
		}
		if len(t.Peer.AllowedIPs) == 0 {
			return nil, fmt.Errorf("tunnel %q: peer.allowed_ips is required", t.Name)
		}
	}
	return &cfg, nil
}

func (c *Config) normalise() {
	if c.ListenHost == "" {
		c.ListenHost = "127.0.0.1"
	}
	if c.PortBase == 0 {
		c.PortBase = 3000
	}
	if c.HTTPOffset == 0 {
		c.HTTPOffset = 1000
	}
	if c.VerifyURL == "" {
		c.VerifyURL = "https://api.ipify.org"
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if t.Port == 0 {
			t.Port = c.PortBase + i
		}
		if t.HTTPPort == 0 && c.HTTPOffset > 0 {
			t.HTTPPort = t.Port + c.HTTPOffset
		}
		if t.MTU == 0 {
			t.MTU = 1420
		}
		if len(t.DNS) == 0 {
			t.DNS = []string{"1.1.1.1", "8.8.8.8"}
		}
	}
}