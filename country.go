package main

// Country-targeted proxies.
//
// HMA's discovery endpoint accepts ?location_key=<ISO-3166 alpha-2> and returns
// the WireGuard servers for that country (a bare country code selects the whole
// country; a full key like "US-OR-PORTLAND" selects one city). Minting then
// happens against that country's own wrangler, so the tunnel really exits there.
//
// This file adds:
//   - DiscoveryIn(jwt, locationKey)  : discovery filtered to one country/city
//   - CountryDiscovery(jwt)          : the list of countries a token can use
//   - per-proxy Country stored on the Proxy and re-applied on every re-mint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Country is one selectable location returned by discovery.
type Country struct {
	Code     string   `json:"code"`      // ISO alpha-2, e.g. "US"
	Name     string   `json:"name"`      // English name, e.g. "United States"
	Cities   []string `json:"cities"`    // cities that country's servers sit in
	Servers  int      `json:"servers"`   // how many wireguard servers answered
	Flag     string   `json:"flag"`      // emoji flag
	Location string   `json:"location"`  // first location_key (informational)
}

// countryNames maps ISO alpha-2 to an English display name.
var countryNames = map[string]string{
	"AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda",
	"AI": "Anguilla", "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica",
	"AR": "Argentina", "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba",
	"AX": "Aland Islands", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina", "BB": "Barbados",
	"BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Bahrain",
	"BI": "Burundi", "BJ": "Benin", "BL": "Saint Barthelemy", "BM": "Bermuda", "BN": "Brunei",
	"BO": "Bolivia", "BQ": "Caribbean Netherlands", "BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan",
	"BV": "Bouvet Island", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize", "CA": "Canada",
	"CC": "Cocos Islands", "CD": "DR Congo", "CF": "Central African Republic", "CG": "Congo",
	"CH": "Switzerland", "CI": "Ivory Coast", "CK": "Cook Islands", "CL": "Chile", "CM": "Cameroon",
	"CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba", "CV": "Cape Verde",
	"CW": "Curacao", "CX": "Christmas Island", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany",
	"DJ": "Djibouti", "DK": "Denmark", "DM": "Dominica", "DO": "Dominican Republic", "DZ": "Algeria",
	"EC": "Ecuador", "EE": "Estonia", "EG": "Egypt", "EH": "Western Sahara", "ER": "Eritrea",
	"ES": "Spain", "ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands",
	"FM": "Micronesia", "FO": "Faroe Islands", "FR": "France", "GA": "Gabon", "GB": "United Kingdom",
	"GD": "Grenada", "GE": "Georgia", "GF": "French Guiana", "GG": "Guernsey", "GH": "Ghana",
	"GI": "Gibraltar", "GL": "Greenland", "GM": "Gambia", "GN": "Guinea", "GP": "Guadeloupe",
	"GQ": "Equatorial Guinea", "GR": "Greece", "GS": "South Georgia", "GT": "Guatemala", "GU": "Guam",
	"GW": "Guinea-Bissau", "GY": "Guyana", "HK": "Hong Kong", "HM": "Heard Island", "HN": "Honduras",
	"HR": "Croatia", "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
	"IL": "Israel", "IM": "Isle of Man", "IN": "India", "IO": "British Indian Ocean Territory",
	"IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy", "JE": "Jersey", "JM": "Jamaica",
	"JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia",
	"KI": "Kiribati", "KM": "Comoros", "KN": "Saint Kitts and Nevis", "KP": "North Korea",
	"KR": "South Korea", "KW": "Kuwait", "KY": "Cayman Islands", "KZ": "Kazakhstan", "LA": "Laos",
	"LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia",
	"LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya",
	"MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro", "MF": "Saint Martin",
	"MG": "Madagascar", "MH": "Marshall Islands", "MK": "North Macedonia", "ML": "Mali",
	"MM": "Myanmar", "MN": "Mongolia", "MO": "Macao", "MP": "Northern Mariana Islands",
	"MQ": "Martinique", "MR": "Mauritania", "MS": "Montserrat", "MT": "Malta", "MU": "Mauritius",
	"MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique",
	"NA": "Namibia", "NC": "New Caledonia", "NE": "Niger", "NF": "Norfolk Island", "NG": "Nigeria",
	"NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru",
	"NU": "Niue", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru",
	"PF": "French Polynesia", "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
	"PL": "Poland", "PM": "Saint Pierre and Miquelon", "PN": "Pitcairn", "PR": "Puerto Rico",
	"PS": "Palestine", "PT": "Portugal", "PW": "Palau", "PY": "Paraguay", "QA": "Qatar",
	"RE": "Reunion", "RO": "Romania", "RS": "Serbia", "RU": "Russia", "RW": "Rwanda",
	"SA": "Saudi Arabia", "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden",
	"SG": "Singapore", "SH": "Saint Helena", "SI": "Slovenia", "SJ": "Svalbard and Jan Mayen",
	"SK": "Slovakia", "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal", "SO": "Somalia",
	"SR": "Suriname", "SS": "South Sudan", "ST": "Sao Tome and Principe", "SV": "El Salvador",
	"SX": "Sint Maarten", "SY": "Syria", "SZ": "Eswatini", "TC": "Turks and Caicos Islands",
	"TD": "Chad", "TF": "French Southern Territories", "TG": "Togo", "TH": "Thailand",
	"TJ": "Tajikistan", "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia",
	"TO": "Tonga", "TR": "Turkiye", "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan",
	"TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda", "UM": "U.S. Minor Outlying Islands",
	"US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VA": "Vatican City",
	"VC": "Saint Vincent and the Grenadines", "VE": "Venezuela", "VG": "British Virgin Islands",
	"VI": "U.S. Virgin Islands", "VN": "Viet Nam", "VU": "Vanuatu", "WF": "Wallis and Futuna",
	"WS": "Samoa", "YE": "Yemen", "YT": "Mayotte", "ZA": "South Africa", "ZM": "Zambia",
	"ZW": "Zimbabwe",
}

// flagEmoji turns "US" into the regional-indicator flag.
func flagEmoji(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return ""
	}
	var b strings.Builder
	for _, r := range code {
		if r < 'A' || r > 'Z' {
			return ""
		}
		b.WriteRune(rune(0x1F1E6 + (r - 'A')))
	}
	return b.String()
}

// CountryName returns the English name for an ISO code (falls back to the code).
func CountryName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if n, ok := countryNames[code]; ok {
		return n
	}
	return code
}

// discoveryURL builds the discovery endpoint, optionally filtered by location.
func discoveryURL(locationKey string) string {
	if locationKey == "" {
		return sePlatform
	}
	return sePlatform + "?location_key=" + strings.TrimSpace(locationKey)
}

// DiscoveryIn returns the WireGuard servers for one country/city key.
// An empty key means "whatever discovery picks by default".
func DiscoveryIn(jwt, locationKey string) ([]HMAServer, error) {
	req, err := http.NewRequest("GET", discoveryURL(locationKey), nil)
	if err != nil {
		return nil, err
	}
	applyDiscoveryHeaders(req, jwt)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("discovery(%s): HTTP %d: %s", locationKey, resp.StatusCode, short(body))
	}
	return parseDiscovery(body)
}

// countryProbeCodes is the ISO alpha-2 set probed to build the country list.
var countryProbeCodes = strings.Fields(`AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW`)

var (
	countryCacheMu sync.Mutex
	countryCache   []Country
	countryCacheAt time.Time
	countryScanRun bool
)

const countryCacheTTL = 30 * time.Minute

// CountryDiscovery probes every ISO code in parallel and returns the countries
// this token can actually reach. Results are cached for countryCacheTTL.
func CountryDiscovery(jwt string) ([]Country, error) {
	countryCacheMu.Lock()
	if len(countryCache) > 0 && time.Since(countryCacheAt) < countryCacheTTL {
		out := append([]Country(nil), countryCache...)
		countryCacheMu.Unlock()
		return out, nil
	}
	countryCacheMu.Unlock()

	type res struct {
		code  string
		servs []HMAServer
		geos  []discoveryGeo
		err   error
	}
	sem := make(chan struct{}, 24)
	out := make(chan res, len(countryProbeCodes))
	var wg sync.WaitGroup
	for _, code := range countryProbeCodes {
		wg.Add(1)
		go func(code string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			servs, geos, err := discoveryGeoIn(jwt, code)
			out <- res{code: code, servs: servs, geos: geos, err: err}
		}(code)
	}
	wg.Wait()
	close(out)

	list := make([]Country, 0, 128)
	for r := range out {
		if r.err != nil || len(r.servs) == 0 {
			continue
		}
		cities := make([]string, 0, 4)
		seenCity := map[string]bool{}
		loc := ""
		for _, g := range r.geos {
			if g.City != "" && !seenCity[g.City] {
				seenCity[g.City] = true
				cities = append(cities, g.City)
			}
			if loc == "" && g.LocationKey != "" {
				loc = g.LocationKey
			}
		}
		sort.Strings(cities)
		list = append(list, Country{
			Code:     r.code,
			Name:     CountryName(r.code),
			Cities:   cities,
			Servers:  len(r.servs),
			Flag:     flagEmoji(r.code),
			Location: loc,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })

	countryCacheMu.Lock()
	countryCache = list
	countryCacheAt = time.Now()
	countryCacheMu.Unlock()
	return list, nil
}

// discoveryGeoIn runs discovery for one location key and returns both the
// servers and their raw geo records.
func discoveryGeoIn(jwt, locationKey string) ([]HMAServer, []discoveryGeo, error) {
	req, err := http.NewRequest("GET", discoveryURL(locationKey), nil)
	if err != nil {
		return nil, nil, err
	}
	applyDiscoveryHeaders(req, jwt)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var dr discoveryResp
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, nil, err
	}
	servs := serversFrom(dr)
	geos := make([]discoveryGeo, 0, len(dr.Data.IPs))
	for _, ip := range dr.Data.IPs {
		if ip.Protocol == "wireguard" {
			geos = append(geos, ip.Geo)
		}
	}
	return servs, geos, nil
}
