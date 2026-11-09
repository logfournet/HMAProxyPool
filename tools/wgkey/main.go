package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	privB64 := strings.TrimSpace(string(raw))
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(priv) != 32 {
		panic(fmt.Sprintf("bad key: %v len=%d", err, len(priv)))
	}
	var k [32]byte
	copy(k[:], priv)
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &k)
	fmt.Printf("private_b64 = %s\n", privB64)
	fmt.Printf("private_hex = %s\n", hex.EncodeToString(priv))
	fmt.Printf("public_b64  = %s\n", base64.StdEncoding.EncodeToString(pub[:]))
	fmt.Printf("public_hex  = %s\n", hex.EncodeToString(pub[:]))
}