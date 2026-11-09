package main

// JWT helpers: expiry decoding plus a file watcher that keeps a live token
// feed attached to the manager.
//
// The HMA access token only lives ~8h, so a long-running proxy set needs a way
// to pick up a fresh one without a restart. A separate helper (tools/hmatoken)
// writes the token it harvested to a file; hgproxy watches that file and
// swaps the token in every key as soon as the content changes.

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"
)

// jwtClaims is the subset of the HMA token payload we care about.
type jwtClaims struct {
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat"`
	Iss  string `json:"iss"`
	Sub  string `json:"sub"`
	Scope string `json:"scope"`
}

// decodeJWT parses the payload without verifying the signature. We only need
// metadata, and discovery will reject a token that is not real anyway.
func decodeJWT(token string) (*jwtClaims, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// tolerate padded payloads
		raw, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, false
		}
	}
	var c jwtClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, false
	}
	return &c, true
}

// jwtExpiry returns the exp claim as wall-clock time.
func jwtExpiry(token string) (time.Time, bool) {
	c, ok := decodeJWT(token)
	if !ok || c.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(c.Exp, 0), true
}

// describeToken renders a short human summary used in logs and API notes.
func describeToken(token string) string {
	c, ok := decodeJWT(token)
	if !ok {
		return "unparsable token"
	}
	left := time.Until(time.Unix(c.Exp, 0)).Round(time.Minute)
	if left <= 0 {
		return "token expired"
	}
	return "token valid for " + left.String()
}

// readTokenFile returns the trimmed contents of path.
func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// watchTokenFile polls path and calls onChange whenever the token changes.
// It keeps running until stop is closed.
func watchTokenFile(path string, interval time.Duration, stop <-chan struct{}, onChange func(string)) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	var last string
	if cur, err := readTokenFile(path); err == nil {
		last = cur
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		cur, err := readTokenFile(path)
		if err != nil || cur == "" || cur == last {
			continue
		}
		if _, ok := jwtExpiry(cur); !ok {
			log.Printf("[token] %s changed but does not look like a JWT, ignoring", path)
			continue
		}
		last = cur
		onChange(cur)
	}
}
