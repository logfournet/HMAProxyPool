package main

// Token ingestion for the pool:
//   - a watched token file (jwt.txt from the HMA service, or any paste)
//   - on Windows, optional live import from the running HMA service
//     (shells out to hmatoken.exe; the import needs admin).

import (
	"log"
	"time"
)

// startTokenFeed watches path and points every key at the new token whenever it
// changes, then asks all live tunnels to re-mint. Returns a stop func.
func startTokenFeed(mgr *Manager, path string) func() {
	stop := make(chan struct{})
	go watchTokenFile(path, 5*time.Second, stop, func(tok string) {
		n := mgr.SetAllTokens(tok)
		log.Printf("[token] new token from %s (%s), refreshed %d key(s)", path, describeToken(tok), n)
		if n > 0 {
			mgr.RenewAll()
		}
	})
	return func() { close(stop) }
}
