//go:build !windows

package main

// ImportTokenFromService is a no-op off Windows; on Linux the token comes from
// a file (paste it in Settings or point at a jwt.txt feed).

import "fmt"

func ImportTokenFromService() (string, error) {
	return "", fmt.Errorf("live HMA import is Windows-only (it reads the VpnSvc.exe process); paste the token in Settings or use a token file")
}
