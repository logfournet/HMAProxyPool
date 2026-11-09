# HMAProxyPool — External API

REST API for external clients. Every endpoint lives under `/api/v1` and is
authenticated with an **API key** created from the dashboard (**APIs** tab).
These keys are separate from the dashboard password and from the HMA tokens.

- Base URL: `http://<host>:8899/api/v1`
- All requests and responses are JSON (except `?format=socks5|http` which
  returns plain text, one URL per line).

---

## Authentication

Send the key with either header:

```
Authorization: Bearer hmap_xxxxxxxxxxxxxxxxxxxxxxxx
X-API-Key: hmap_xxxxxxxxxxxxxxxxxxxxxxxx
```

| Key type     | Can do                                        |
|--------------|-----------------------------------------------|
| **Full Control** (`read` + `write`) | everything: create, rotate, delete, change settings |
| **Read Only** (`read`) | `GET` endpoints only — writes return `403` |

Errors:

| Status | Meaning                                      |
|--------|----------------------------------------------|
| `401`  | missing/unknown/revoked key (`{"error":"invalid or missing API key"}`) |
| `403`  | read-only key used for a write (`{"error":"this API key is read-only"}`) |
| `400`  | bad request body / unknown id                |
| `502`  | upstream HMA error (discovery/wrangler)      |

Requests are counted per key (`requests`, `last_used`). The full token can be
revealed again in the dashboard at any time.

---

## Endpoints

### `GET /me`
Key info and pool totals.

```json
{
  "key":  {"id":"0c7c54f0","name":"my-client","prefix":"hmap_80eb24d9a",
           "scopes":["read","write"],"requests":1,"can_write":true},
  "pool": {"proxies":41,"up":41,"down":0},
  "version":"1.0.0"
}
```

### `GET /proxies`
List every proxy, sorted by ping (lowest first; proxies without a ping yet go
last). Optional query params:

| Param     | Values                        | Effect                          |
|-----------|-------------------------------|---------------------------------|
| `format`  | `socks5` / `http`             | plain text list of URLs instead of JSON |
| `state`   | `up` / `down`                 | filter by state                 |
| `country` | `US`, `VN`, … (case-insensitive) | only proxies whose **measured** exit country matches |

Each proxy (the response wrapper is `{"count":n,"proxies":[…]}`):

```json
{
  "id":"p12-d08f80","name":"dj-12","key_id":"2dda4edf64a4",
  "socks5":"socks5://127.0.0.1:3011","http":"http://127.0.0.1:4011",
  "port":3011,"http_port":4011,"sessions":1,
  "created_at":"2026-11-09T15:56:16+07:00",
  "state":"up","up":true,
  "session_ctip":"100.120.63.239/32","session_age_sec":18,
  "remints":0,"hedges":0,"dials":4,"errors":0,
  "rx_bytes":18360,"tx_bytes":11792,"last_error":"",
  "country":"Viet Nam","country_code":"VN","flag":"🇻🇳",
  "ping_ms":37,"exit_ip":"156.59.140.20"
}
```

Notes:
- `country`/`flag`/`ping_ms`/`exit_ip` are measured through the tunnel and
  cached ~120 s; they may be briefly missing right after a proxy comes up.
- `socks5`/`http` URLs embed `user:pass@` when a shared proxy credential is
  configured in Settings.
- Bind address comes from Settings (`127.0.0.1` = local only,
  `0.0.0.0` = reachable from the network).

### `GET /proxies?format=socks5` (or `format=http`)
Plain text, one URL per line — handy for proxy rotators:

```
socks5://127.0.0.1:3011
socks5://127.0.0.1:3016
socks5://127.0.0.1:3022
```

### `GET /proxies/{id}`
One proxy (same shape as above, without `proxies[]` wrapper).

### `POST /proxies`
Create proxies. Body:

```json
{"key_id":"2dda4edf64a4","count":2,"sessions":1,"country":"US"}
```

- `key_id` optional when exactly one HMA key is registered.
- `count` 1–64 (default 1).
- `sessions` 1–4.
- `country` ISO alpha-2 (`"US"`) or full location key
  (`"US-OR-PORTLAND"`); `""`/`"ANY"` = HMA's default (nearest).

Returns `202 Accepted` — creation happens in the background (each tunnel
takes a few seconds to mint):

```json
{"queued":true,"key_id":"…","count":2,"sessions":1,"country":"US"}
```

### `POST /proxies/{id}/rotate`
Force a re-mint: the proxy gets a new session and a new exit IP (stays on the
same port and requested country). Returns `{"id":"…","rotated":true}`.

### `GET /proxies/{id}/verify`
Fetch the current exit IP through the tunnel (bypasses the geo cache — use
right after a rotate). Returns `{"id":"…","exit_ip":"128.1.126.120"}`.

### `DELETE /proxies/{id}`
Delete one proxy.

### `POST /proxies/bulk-delete`
Delete many. Body: `{"ids":["p12-d08f80","p13-…"]}` → `{"deleted":2}`.

### `POST /geo/refresh`
Re-measure country + ping for every proxy now (`{"refreshing":true}`).

### `GET /countries`
All countries the active HMA token can create proxies in
(`{"countries":[{"code":"US","name":"United States","cities":["Honolulu"],
"servers":2,"flag":"🇺🇸","location":"US-HI-HONOLULU"}],"count":104}`).

### `GET /keys` · `POST /keys` · `DELETE /keys/{id}`
Manage HMA tokens (the upstream credentials proxies are minted from).
`POST /keys` body: `{"name":"my-key","token":"<JWT>"}`.

### `GET /settings` · `POST /settings`
Read/patch pool settings. `POST` accepts any subset (pointer semantics —
omitted fields stay unchanged):

```json
{"listen_host":"0.0.0.0","proxy_user":"alice","proxy_pass":"secret",
 "port_base":3000,"http_offset":1000,"sessions":1,
 "probe_url":"https://icanhazip.com/","token_file":"jwt.txt"}
```

- `listen_host`: `127.0.0.1` or `0.0.0.0`.
- `proxy_user`/`proxy_pass`: shared credential for **every** proxy in the
  pool (both empty = open proxy). Applies to proxies created afterwards —
  rebuild the pool (dashboard **Settings → Rebuild Proxies**) to apply to
  running ones.

---

## Quick start

```bash
# list every proxy as json
curl -H "Authorization: Bearer hmap_xxx" http://127.0.0.1:8899/api/v1/proxies

# plain socks5 list, one url per line
curl -H "X-API-Key: hmap_xxx" "http://127.0.0.1:8899/api/v1/proxies?format=socks5"

# only up proxies in the US
curl -H "Authorization: Bearer hmap_xxx" \
  "http://127.0.0.1:8899/api/v1/proxies?state=up&country=US"

# create 2 proxies in the united states
curl -X POST -H "Authorization: Bearer hmap_xxx" \
  -d '{"count":2,"country":"US","sessions":1}' \
  http://127.0.0.1:8899/api/v1/proxies

# rotate one proxy, then verify its new exit ip
curl -X POST -H "Authorization: Bearer hmap_xxx" http://127.0.0.1:8899/api/v1/proxies/p12-d08f80/rotate
curl -H "Authorization: Bearer hmap_xxx" http://127.0.0.1:8899/api/v1/proxies/p12-d08f80/verify

# delete it
curl -X DELETE -H "Authorization: Bearer hmap_xxx" http://127.0.0.1:8899/api/v1/proxies/p12-d08f80
```

Python example:

```python
import requests

BASE = "http://127.0.0.1:8899/api/v1"
H = {"Authorization": "Bearer hmap_xxx"}

proxies = requests.get(f"{BASE}/proxies?state=up", headers=H).json()["proxies"]
best = proxies[0]                      # sorted by ping, lowest first
print(best["flag"], best["country"], best["ping_ms"], "ms")

# use it
r = requests.get("https://icanhazip.com",
                 proxies={"http": best["socks5"], "https": best["socks5"]})
print("exit ip:", r.text.strip())
```

---

## Managing API keys

API keys are managed from the dashboard (**APIs** tab) or with the dashboard
cookie session:

```
GET    /api/apikeys        list keys (full token included, mask in your own UI)
POST   /api/apikeys        {"name":"my-client","write":true} → {"token":"hmap_…","key":{…}}
DELETE /api/apikeys/{id}   revoke
```

Deleted keys stop working immediately. The dashboard itself (`/api/*`) keeps
using the password login — API keys only open `/api/v1/*`.
