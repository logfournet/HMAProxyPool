//go:build windows

package main

// ImportTokenFromService harvests the live HMA access token from the running
// VpnSvc.exe via the separately built hmatoken.exe helper (same directory or on
// PATH). Reading another process' memory needs elevation, so this fails with a
// helpful message when the shell is not admin.
//
// The helper writes the token to a temp file and exits; we read it back.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ImportTokenFromService() (string, error) {
	helper := findHelper()
	if helper == "" {
		return "", fmt.Errorf("hmatoken.exe not found next to this program or on PATH; build it with: go build -o hmatoken.exe ./tools/hmatoken")
	}
	dir, err := os.MkdirTemp("", "hmapool-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "jwt.txt")

	cmd := exec.Command(helper, "-out", out, "-quiet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if strings.Contains(msg, "Access is denied") || strings.Contains(msg, "access is denied") {
			return "", fmt.Errorf("access denied reading the HMA service — run HMAProxyPool as Administrator to import the live token")
		}
		return "", fmt.Errorf("hmatoken failed: %v (%s)", err, msg)
	}
	tok, err := os.ReadFile(out)
	if err != nil {
		return "", fmt.Errorf("hmatoken ran but wrote no token: %v", err)
	}
	t := strings.TrimSpace(string(tok))
	if t == "" {
		return "", fmt.Errorf("hmatoken found no token — is the HMA client signed in?")
	}
	return t, nil
}

// findHelper looks for hmatoken.exe next to this executable, then on PATH.
func findHelper() string {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "hmatoken.exe")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	if p, err := exec.LookPath("hmatoken.exe"); err == nil {
		return p
	}
	return ""
}
