// Command hmatoken harvests the live HMA access token out of the running
// HMA VPN service and writes it to a file that hgproxy watches.
//
// The HMA client keeps its decrypted token store in memory as
// {"access_token":"...","refresh_token":"..."} and never writes it anywhere
// readable: the on-disk copy is a machine-scope DPAPI blob. Reading another
// user's (SYSTEM's) process memory therefore needs an elevated process, which
// is why this tool must run as Administrator / LocalSystem.
//
// Typical use is a one-time scheduled task that keeps the feed fresh:
//
//	hmatoken.exe -out C:\hgproxy\jwt.txt -interval 5m
//
// hgproxy then reloads the token on every change (-jwt flag), re-mints the
// tunnels and keeps the proxies up across token expiry, with no HMA client
// interaction at all.
//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ------------------------------------------------------------------ winapi

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess     = kernel32.NewProc("OpenProcess")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
	procReadProcessMem  = kernel32.NewProc("ReadProcessMemory")
	procVirtualQueryEx  = kernel32.NewProc("VirtualQueryEx")
	procIsWow64Process2 = kernel32.NewProc("IsWow64Process2")
)

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010

	memCommit  = 0x1000
	memPrivate = 0x20000

	pageNoAccess = 0x01
	pageGuard    = 0x100
)

// memoryBasicInformation mirrors MEMORY_BASIC_INFORMATION64.
type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	_                 uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

const mbiSize = int(unsafe.Sizeof(memoryBasicInformation{}))

func openProcess(pid int) (syscall.Handle, error) {
	r, _, err := procOpenProcess.Call(processQueryInformation|processVMRead, 0, uintptr(pid))
	if r == 0 {
		return 0, err
	}
	return syscall.Handle(r), nil
}

func closeHandle(h syscall.Handle) {
	_, _, _ = procCloseHandle.Call(uintptr(h))
}

func virtualQueryEx(h syscall.Handle, addr uintptr) (*memoryBasicInformation, error) {
	var mbi memoryBasicInformation
	r, _, err := procVirtualQueryEx.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&mbi)), uintptr(mbiSize))
	if r == 0 {
		return nil, err
	}
	return &mbi, nil
}

func readProcessMemory(h syscall.Handle, addr uintptr, buf []byte) (int, error) {
	var n uintptr
	r, _, err := procReadProcessMem.Call(
		uintptr(h), addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return 0, err
	}
	return int(n), nil
}

// --------------------------------------------------------------- scanning

// tokenMarkers are the byte patterns that directly precede the access token in
// the service's JSON token store. The store is built by two different code
// paths (narrow and wide JSON), so both encodings are searched.
var tokenMarkers = [][]byte{
	[]byte(`"access_token":"`),
	utf16le(`"access_token":"`),
	[]byte(`access_token":"`),
	utf16le(`access_token":"`),
}

// jwtPrefixes are the bare starts of a JWT. They are searched as a fallback so
// the tool still works when the surrounding JSON layout changes (different
// quoting, extra whitespace, a struct instead of a map).
var jwtPrefixes = [][]byte{
	[]byte("eyJ"),
	[]byte("e\x00y\x00J\x00"),
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

// looksLikeJWT is a cheap structural check: three base64url segments, the first
// two starting with the usual "eyJ".
func looksLikeJWT(s string) bool {
	if len(s) < 100 || len(s) > 4000 {
		return false
	}
	if !strings.HasPrefix(s, "eyJ") {
		return false
	}
	if strings.Count(s, ".") != 2 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// extractAfter pulls a token out of buf starting at off, honouring the stride
// (1 for narrow strings, 2 for UTF-16LE).
func extractAfter(buf []byte, off, stride int) string {
	var sb strings.Builder
	for i := off; i+stride <= len(buf) && sb.Len() < 4096; i += stride {
		c := buf[i]
		if c == '"' || c < 0x20 || c > 0x7e {
			break
		}
		sb.WriteByte(c)
	}
	s := sb.String()
	if looksLikeJWT(s) {
		return s
	}
	return ""
}

// scanBuffer returns every plausible JWT found in buf.
func scanBuffer(buf []byte, found map[string]struct{}) {
	for _, m := range tokenMarkers {
		stride := 1
		if len(m) > 1 && m[1] == 0 {
			stride = 2
		}
		base := 0
		for {
			i := bytes.Index(buf[base:], m)
			if i < 0 {
				break
			}
			start := base + i + len(m)
			if tok := extractAfter(buf, start, stride); tok != "" {
				found[tok] = struct{}{}
			}
			base += i + len(m)
		}
	}
	// fallback: any bare JWT start, whatever the surrounding layout
	for _, m := range jwtPrefixes {
		stride := 1
		if len(m) > 1 && m[1] == 0 {
			stride = 2
		}
		base := 0
		for {
			i := bytes.Index(buf[base:], m)
			if i < 0 {
				break
			}
			if tok := extractAfter(buf, base+i, stride); tok != "" {
				found[tok] = struct{}{}
			}
			base += i + 1
		}
	}
}

// harvest scans the private committed memory of pid and returns every JWT it
// can find, ordered by scan order.
func harvest(pid int) ([]string, error) {
	h, err := openProcess(pid)
	if err != nil {
		return nil, err
	}
	defer closeHandle(h)

	const chunk = 4 << 20 // 4 MiB reads with a small overlap
	const overlap = 4096

	found := map[string]struct{}{}
	var order []string
	buf := make([]byte, chunk+overlap)

	var addr uintptr
	for {
		mbi, err := virtualQueryEx(h, addr)
		if err != nil {
			break
		}
		regionEnd := mbi.BaseAddress + mbi.RegionSize
		usable := mbi.State == memCommit &&
			mbi.Protect&pageNoAccess == 0 &&
			mbi.Protect&pageGuard == 0

		if usable && mbi.Type == memPrivate {
			for a := mbi.BaseAddress; a < regionEnd; {
				want := regionEnd - a
				if want > chunk {
					want = chunk
				}
				n, err := readProcessMemory(h, a, buf[:want])
				if err == nil && n > 0 {
					before := len(found)
					scanBuffer(buf[:n], found)
					if len(found) > before {
						for k := range found {
							dup := false
							for _, o := range order {
								if o == k {
									dup = true
									break
								}
							}
							if !dup {
								order = append(order, k)
							}
						}
					}
				}
				if want <= overlap {
					break
				}
				a += want - overlap
			}
		}

		if regionEnd <= addr {
			break
		}
		addr = regionEnd
	}
	return order, nil
}

// ------------------------------------------------------------------- jwt

func jwtExp(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	// base64url without padding
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	raw, err := base64URLDecode(payload)
	if err != nil {
		return time.Time{}, false
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(c.Exp, 0), true
}

func base64URLDecode(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var idx [256]int
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		idx[alphabet[i]] = i
	}
	var out []byte
	var acc, bits uint
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		v := idx[c]
		if v < 0 {
			return nil, fmt.Errorf("bad base64 char %q", c)
		}
		acc = acc<<6 | uint(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out, nil
}

// --------------------------------------------------------------- process

// findProcessPIDs returns every pid whose image name matches want (case
// insensitive, with or without .exe).
func findProcessPIDs(want string) ([]int, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer closeHandle(snap)

	var pids []int
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := syscall.Process32First(snap, &pe); err != nil {
		return nil, err
	}
	wantLower := strings.ToLower(strings.TrimSuffix(want, ".exe"))
	for {
		name := strings.ToLower(strings.TrimSuffix(syscall.UTF16ToString(pe.ExeFile[:]), ".exe"))
		if name == wantLower {
			pids = append(pids, int(pe.ProcessID))
		}
		if err := syscall.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return pids, nil
}

// writeAtomic replaces path with data, so a watcher never sees a partial file.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hmatoken-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// readIfExists returns the trimmed contents of path, or "" when unreadable.
func readIfExists(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// payloadContains reports whether the JWT payload contains sub.
func payloadContains(token, sub string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	p := parts[1]
	switch len(p) % 4 {
	case 2:
		p += "=="
	case 3:
		p += "="
	}
	raw, err := base64URLDecode(p)
	if err != nil {
		return false
	}
	return bytes.Contains(raw, []byte(sub))
}

// tokenIssuer returns the iss claim, for log lines only.
func tokenIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "?"
	}
	p := parts[1]
	switch len(p) % 4 {
	case 2:
		p += "=="
	case 3:
		p += "="
	}
	raw, err := base64URLDecode(p)
	if err != nil {
		return "?"
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Iss == "" {
		return "?"
	}
	return c.Iss
}

// bestToken picks the HMA token with the furthest expiry. Tokens whose issuer
// is not HMA's "elysium" are only used when nothing better is available, which
// keeps unrelated JWTs from other software out of the feed.
func bestToken(tokens []string) (string, time.Time, bool) {
	pick := func(onlyHMA bool) (string, time.Time, bool) {
		var best string
		var bestExp time.Time
		for _, t := range tokens {
			if onlyHMA && !payloadContains(t, "elysium") {
				continue
			}
			exp, ok := jwtExp(t)
			if !ok {
				continue
			}
			if best == "" || exp.After(bestExp) {
				best, bestExp = t, exp
			}
		}
		return best, bestExp, best != ""
	}
	if t, e, ok := pick(true); ok {
		return t, e, true
	}
	return pick(false)
}

func main() {
	var (
		procName = flag.String("process", "VpnSvc.exe", "name of the HMA service process to read")
		out      = flag.String("out", "jwt.txt", "token file to write (hgproxy -jwt watches this)")
		interval = flag.Duration("interval", 0, "keep running and re-check this often (0 = one shot)")
		minTTL   = flag.Duration("min-ttl", 30*time.Minute, "warn when the harvested token has less than this left")
		logPath  = flag.String("log", "", "append logs to this file (needed when run as a SYSTEM task, where stderr is discarded)")
		quiet    = flag.Bool("quiet", false, "only log warnings and token changes")
	)
	flag.Parse()

	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("[hmatoken] cannot open log %s: %v", *logPath, err)
		} else {
			log.SetOutput(f)
			defer f.Close()
		}
	}
	log.SetFlags(log.LstdFlags)

	info := func(format string, a ...any) {
		if !*quiet {
			log.Printf(format, a...)
		}
	}

	lastWrite := ""

	runOnce := func() bool {
		pids, err := findProcessPIDs(*procName)
		if err != nil {
			log.Printf("[hmatoken] enumerate processes: %v", err)
			return false
		}
		if len(pids) == 0 {
			log.Printf("[hmatoken] %s is not running", *procName)
			return false
		}

		var all []string
		var lastErr error
		for _, pid := range pids {
			toks, err := harvest(pid)
			if err != nil {
				lastErr = err
				continue
			}
			all = append(all, toks...)
		}
		if len(all) == 0 {
			if lastErr != nil {
				log.Printf("[hmatoken] cannot read %s memory: %v (run elevated / as LocalSystem)", *procName, lastErr)
			} else {
				log.Printf("[hmatoken] no token found in %s; is the client signed in?", *procName)
			}
			return false
		}

		token, exp, ok := bestToken(all)
		if !ok {
			log.Printf("[hmatoken] found %d candidate(s) but none decoded as a JWT", len(all))
			return false
		}
		info("[hmatoken] %d JWT(s) in memory, chose one from %s", len(all), tokenIssuer(token))

		left := time.Until(exp).Round(time.Second)
		if left < *minTTL {
			log.Printf("[hmatoken] WARNING token expires in %s (%s)", left, exp.Format(time.RFC3339))
		}

		if token == lastWrite && readIfExists(*out) == token {
			info("[hmatoken] token unchanged (%s left)", left.Round(time.Minute))
			lastWrite = token
			return true
		}
		if err := writeAtomic(*out, []byte(token+"\n")); err != nil {
			log.Printf("[hmatoken] write %s: %v", *out, err)
			return false
		}
		lastWrite = token
		log.Printf("[hmatoken] wrote %s (%d bytes, expires in %s)", *out, len(token), left.Round(time.Minute))
		return true
	}

	if *interval <= 0 {
		if !runOnce() {
			os.Exit(1)
		}
		return
	}

	info("[hmatoken] watching %s every %s, writing %s", *procName, *interval, *out)
	for {
		runOnce()
		time.Sleep(*interval)
	}
}
