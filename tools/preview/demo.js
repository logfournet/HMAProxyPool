// Demo data for the README preview image.
//
// tools/preview/render.js injects this file into web/index.html *before* the
// app boots and replaces window.fetch, so the dashboard renders without a
// server, without an HMA token and without any real proxy. Every address here
// is documentation-only (RFC 5737 / RFC 6598), so the screenshot never leaks
// a real exit IP or key.
(function () {
  const now = new Date().toISOString();

  const PROXIES = [
    ['p1-4c81aa', 'vn-fast', 'VN', 'Viet Nam', 12, '203.0.113.24', 3011, 4011, '100.64.112.31/32', 14820, 9210],
    ['p2-9d3f10', 'sg-edge', 'SG', 'Singapore', 34, '198.51.100.77', 3016, 4016, '100.64.118.9/32', 9240, 5810],
    ['p3-7ab204', 'jp-tokyo', 'JP', 'Japan', 58, '203.0.113.140', 3022, 4022, '100.64.121.55/32', 22180, 13470],
    ['p4-1f65ce', 'kr-seoul', 'KR', 'South Korea', 71, '192.0.2.88', 3028, 4028, '100.64.126.18/32', 6110, 3980],
    ['p5-8be013', 'de-frankfurt', 'DE', 'Germany', 96, '198.51.100.19', 3034, 4034, '100.64.131.72/32', 30450, 17260],
    ['p6-2cd77b', 'gb-london', 'GB', 'United Kingdom', 118, '203.0.113.201', 3040, 4040, '100.64.137.44/32', 7410, 4620],
    ['p7-6e19f5', 'us-ashburn', 'US', 'United States', 164, '192.0.2.146', 3046, 4046, '100.64.142.90/32', 41230, 24810],
    ['p8-3a5c28', 'au-sydney', 'AU', 'Australia', 187, '198.51.100.233', 3052, 4052, '100.64.149.7/32', 1820, 940],
  ];

  const proxies = PROXIES.map(function (p) {
    return {
      id: p[0], name: p[1], key_id: 'k1',
      country: p[3], country_code: p[2], country_requested: p[2],
      ping_ms: p[4], exit_ip: p[5],
      socks5: 'socks5://127.0.0.1:' + p[6],
      http: 'http://127.0.0.1:' + p[7],
      port: p[6], http_port: p[7],
      sessions: 1, created_at: now, state: 'up', up: true,
      session_ctip: p[8], session_age_sec: 3600, dials: 12, rx_bytes: p[9], tx_bytes: p[10],
    };
  });

  const keys = [
    { id: 'k1', name: 'main', status: 'ok', note: '2 wireguard servers visible; token valid for 6h12m0s', expires_at: '2026-11-09T22:41:00+07:00', added_at: now, plan_count: 6, proxies: 6 },
    { id: 'k2', name: 'backup', status: 'ok', note: 'token valid for 2h48m0s', expires_at: '2026-11-09T19:17:00+07:00', added_at: now, plan_count: 2, proxies: 2 },
  ];

  const COUNTRIES = [
    ['VN', 'Viet Nam', ['Hanoi', 'Ho Chi Minh'], 8, 'VN-HN-HANOI'],
    ['SG', 'Singapore', ['Singapore'], 2, 'SG-SINGAPORE'],
    ['JP', 'Japan', ['Tokyo', 'Osaka'], 2, 'JP-TOKYO'],
    ['KR', 'South Korea', ['Seoul'], 2, 'KR-SEOUL'],
    ['DE', 'Germany', ['Frankfurt', 'Berlin'], 2, 'DE-FRANKFURT'],
    ['GB', 'United Kingdom', ['London'], 2, 'GB-LONDON'],
    ['US', 'United States', ['Ashburn', 'Los Angeles'], 2, 'US-VA-ASHBURN'],
    ['AU', 'Australia', ['Sydney'], 2, 'AU-SYDNEY'],
    ['CA', 'Canada', ['Toronto'], 2, 'CA-ON-TORONTO'],
    ['FR', 'France', ['Paris'], 2, 'FR-PARIS'],
    ['NL', 'Netherlands', ['Amsterdam'], 2, 'NL-AMSTERDAM'],
    ['IN', 'India', ['Mumbai'], 2, 'IN-MUMBAI'],
  ].map(function (c) {
    return { code: c[0], name: c[1], cities: c[2], servers: c[3], location: c[4], flag: '' };
  });

  const apikeys = [
    { id: 'ak_9f2b71c4', name: 'scraper-pool', prefix: 'hmap_4c1e88a2b', token: 'hmap_4c1e88a2b0d5f37e91ac6d2405b8e71f9c3a6d5802eb14fa', scopes: 'Read + Write', created_at: '2026-11-08T09:12:00+07:00', last_used: '2026-11-09T16:58:00+07:00', requests: 1284 },
    { id: 'ak_3d80e5aa', name: 'monitoring', prefix: 'hmap_77b0c31fd', token: 'hmap_77b0c31fd6ae902b48c71f05e39d2a6b84c0175fd3e9a2c6', scopes: 'Read Only', created_at: '2026-11-07T14:30:00+07:00', last_used: '2026-11-09T17:01:00+07:00', requests: 9731 },
  ];

  const overview = {
    keys: keys,
    proxies: proxies,
    totals: { proxies: proxies.length, up: proxies.length, down: 0, keys: keys.length },
    settings: {
      port_base: 3000, http_offset: 1000, sessions: 1,
      probe_url: 'https://icanhazip.com/', token_file: 'jwt.txt',
      listen_host: '127.0.0.1', proxy_user: '', proxy_pass: '',
    },
    now: now,
  };

  const ROUTES = {
    '/api/me': { authed: true },
    '/api/overview': overview,
    '/api/countries': { countries: COUNTRIES, count: 104 },
    '/api/apikeys': { keys: apikeys, count: apikeys.length },
  };

  window.fetch = function (url, opts) {
    const p = String(url).split('?')[0];
    let body = ROUTES[p];
    if (body === undefined) body = { ok: true, saved: true, deleted: true };
    const json = JSON.stringify(body);
    return Promise.resolve(new Response(json, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
  };

  // Open a specific tab for the screenshot (?tab=apis) once the app has booted.
  window.addEventListener('load', function () {
    const tab = new URLSearchParams(location.search).get('tab');
    if (!tab || tab === 'proxies') return;
    setTimeout(function () {
      const el = document.querySelector('.tab[data-tab="' + tab + '"]');
      if (el) el.click();
    }, 400);
  });
})();