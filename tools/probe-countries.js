const fs = require('fs');

const JWT = fs.readFileSync('jwt.txt', 'utf8').trim();
const BASE = 'https://api.se-platform.com/discovery/v9/discover';
const HEADERS = {
  'Authorization': 'Bearer ' + JWT,
  'SE-Client-Type': 'hma101',
  'SE-Client-API-Key': 'DECE424681E71043331A3DB13CB0905E03EB605478F1584055ED0EECE80A3E01',
  'SE-Client-Name': 'GVPN',
  'SE-Client-Version': '26.10.12427',
  'X-NLok-Tenant-ID': '3bfdc5ab-a90f-4503-8349-34d0991d33a3',
  'Accept': 'application/json',
  'User-Agent': 'GVPN',
};

const CODES = ('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ ' +
  'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR ' +
  'GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP ' +
  'KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ ' +
  'NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ ' +
  'TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW').split(/\s+/);

async function probe(code) {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 15000);
    const r = await fetch(BASE + '?location_key=' + code, { headers: HEADERS, signal: ctl.signal });
    clearTimeout(t);
    if (!r.ok) return { code, ok: false, status: r.status };
    const j = await r.json();
    const ips = (j.data && j.data.ips) || [];
    const keys = [...new Set(ips.map(x => x.geo && x.geo.location_key).filter(Boolean))];
    const cities = [...new Set(ips.map(x => x.geo && x.geo.city).filter(Boolean))];
    const ccs = [...new Set(ips.map(x => x.geo && x.geo.country_code).filter(Boolean))];
    return { code, ok: true, n: ips.length, ccs, keys, cities };
  } catch (e) {
    return { code, ok: false, err: String(e.message).slice(0, 40) };
  }
}

(async () => {
  const out = [];
  const BATCH = 20;
  for (let i = 0; i < CODES.length; i += BATCH) {
    const part = CODES.slice(i, i + BATCH);
    out.push(...await Promise.all(part.map(probe)));
  }
  const avail = out.filter(x => x.ok && x.n > 0);
  const rejected = out.filter(x => !x.ok);
  console.log('probed:', out.length, ' available:', avail.length, ' rejected:', rejected.length);
  console.log('--- AVAILABLE COUNTRIES ---');
  for (const a of avail) console.log(`${a.code}\t${a.n}\tservers\t${a.keys.join(',')}\t${a.cities.join(',')}`);
  console.log('--- REJECTED (status) ---');
  const byStatus = {};
  rejected.forEach(r => { const k = r.status || r.err; byStatus[k] = (byStatus[k] || 0) + 1; });
  console.log(JSON.stringify(byStatus));
  fs.writeFileSync('countries_probe.json', JSON.stringify(out, null, 1));
})().catch(e => { console.error(e); process.exit(1); });
