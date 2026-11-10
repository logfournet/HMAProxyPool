#!/usr/bin/env node
// Renders web/index.html to a PNG from code — no live pool, no HMA token and
// no manual screenshots. tools/preview/demo.js replaces window.fetch with
// fixed documentation-only data, then headless Chrome rasterises the page.
//
//   node tools/preview/render.js                      -> docs/preview.png
//   node tools/preview/render.js --tab=apis --out=docs/preview-apis.png
//   node tools/preview/render.js --height=1500 --scale=2
//
// Requires a Chrome/Chromium/Edge binary (CHROME_PATH overrides autodetect).
// The page pulls the Geist webfont and the flag images from the network, so
// the first run needs internet access.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { pathToFileURL } = require('url');

const root = path.resolve(__dirname, '..', '..');

function arg(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith('--' + name + '='));
  return hit ? hit.slice(name.length + 3) : fallback;
}

const tab = arg('tab', 'proxies');
const out = path.resolve(root, arg('out', 'docs/preview.png'));
const width = Number(arg('width', 1440));
const height = Number(arg('height', 1180));
const scale = Number(arg('scale', 2));

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const candidates =
    process.platform === 'win32'
      ? [
          'C:/Program Files/Google/Chrome/Application/chrome.exe',
          'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
          path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/Application/chrome.exe'),
          'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
          'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
        ]
      : [
          '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
          '/Applications/Chromium.app/Contents/MacOS/Chromium',
          '/usr/bin/google-chrome',
          '/usr/bin/google-chrome-stable',
          '/usr/bin/chromium',
          '/usr/bin/chromium-browser',
        ];
  for (const c of candidates) {
    if (c && fs.existsSync(c)) return c;
  }
  throw new Error('no Chrome/Chromium found — set CHROME_PATH to the browser binary');
}

const chrome = findChrome();
const html = fs.readFileSync(path.join(root, 'web', 'index.html'), 'utf8');
const demo = fs.readFileSync(path.join(__dirname, 'demo.js'), 'utf8');

// Inject before the app's own <script> so the fetch stub is in place when the
// dashboard boots.
const marker = '</head>';
if (!html.includes(marker)) throw new Error('web/index.html: no </head> to inject into');
const page = html.replace(marker, '<script>\n' + demo + '\n</script>\n' + marker);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-preview-'));
const pagePath = path.join(tmp, 'preview.html');
fs.writeFileSync(pagePath, page);
fs.mkdirSync(path.dirname(out), { recursive: true });

const args = [
  '--headless=new',
  '--disable-gpu',
  '--hide-scrollbars',
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-extensions',
  '--user-data-dir=' + path.join(tmp, 'profile'),
  '--window-size=' + width + ',' + height,
  '--force-device-scale-factor=' + scale,
  '--virtual-time-budget=10000',
  '--screenshot=' + out,
  pathToFileURL(pagePath).href + (tab && tab !== 'proxies' ? '?tab=' + encodeURIComponent(tab) : ''),
];

const run = spawnSync(chrome, args, { encoding: 'utf8' });
if (!fs.existsSync(out)) {
  console.error(run.stdout || '', run.stderr || '');
  throw new Error('chrome produced no screenshot (exit ' + run.status + ')');
}

const kb = (fs.statSync(out).size / 1024).toFixed(0);
console.log('wrote ' + path.relative(root, out) + '  (' + width + 'x' + height + ' @' + scale + 'x, ' + kb + ' KB, tab=' + tab + ')');
fs.rmSync(tmp, { recursive: true, force: true });