package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "1.0.0"

func main() {
	var (
		listen    = flag.String("listen", "127.0.0.1:8899", "dashboard listen address")
		statePath = flag.String("state", "pool.json", "state file (keys, password, settings)")
		password  = flag.String("password", "", "dashboard password (default: auto-generated on first run and printed)")
		portBase  = flag.Int("port-base", 3000, "first SOCKS5 port")
		httpOff   = flag.Int("http-offset", 1000, "HTTP proxy port offset")
		sessions  = flag.Int("sessions", 1, "default sessions per proxy")
		probeURL  = flag.String("probe-url", "https://icanhazip.com/", "liveness/verify URL")
		tokenFile = flag.String("token-file", "", "watched HMA token file (jwt.txt), auto-feeds every key")
		noBrowser = flag.Bool("no-browser", false, "do not open the dashboard automatically")
		verbose   = flag.Bool("verbose", false, "verbose wireguard-go logging")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags)
	if *verbose {
		deviceLogLevel = 2
	}
	if *noBrowser {
		os.Setenv("POOL_NO_BROWSER", "1")
	}

	// ---- state ----
	st, err := loadState(*statePath)
	if err != nil {
		log.Fatalf("state: %v", err)
	}
	provided := *password
	if provided == "" {
		provided = os.Getenv("POOL_PASSWORD")
	}
	pw, err := st.ensurePassword(provided)
	if err != nil {
		log.Fatalf("password: %v", err)
	}
	if pw != "" {
		fmt.Println("=====================================================")
		fmt.Println("  First run. Dashboard password:  " + pw)
		fmt.Println("  (store it somewhere — it is shown only once)")
		fmt.Println("=====================================================")
	}
	_ = st.save(*statePath)

	// ---- manager ----
	if *portBase != 3000 {
		st.Settings.PortBase = *portBase
	}
	if *httpOff != 1000 {
		st.Settings.HTTPOffset = *httpOff
	}
	if *sessions != 1 {
		st.Settings.Sessions = *sessions
	}
	if *probeURL != "https://icanhazip.com/" {
		st.Settings.ProbeURL = *probeURL
	}
	if *tokenFile != "" {
		st.Settings.TokenFile = *tokenFile
	}
	mgr := NewManager("127.0.0.1", st.Settings.PortBase, st.Settings.HTTPOffset, st.Settings.ProbeURL)
	if st.Settings.ListenHost != "" {
		mgr.SetListenHost(st.Settings.ListenHost)
	}
	if st.Settings.ProxyUser != "" {
		mgr.SetAuth(st.Settings.ProxyUser, st.Settings.ProxyPass)
	}

	// ---- restore keys + planned pools ----
	n := st.restoreKeys(mgr)
	log.Printf("[state] restored %d key(s)", n)

	// ---- web app ----
	app := newPoolApp(mgr, st, *statePath, version)
	if st.Settings.TokenFile != "" {
		app.tokenFile = st.Settings.TokenFile
		app.applyTokenFile()
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("dashboard on http://%s  (login to manage the pool)", *listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	openBrowser("http://" + *listen)

	// graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("signal, shutting down")
	if app.tokenStop != nil {
		app.tokenStop()
	}
	_ = srv.Close()
	mgr.Close()
}

// openBrowser opens the dashboard in the default browser.
func openBrowser(url string) {
	if os.Getenv("POOL_NO_BROWSER") == "1" {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux / others
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// humanBytes for the UI summary (kept local so core files stay untouched).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

var _ = strings.TrimSpace
