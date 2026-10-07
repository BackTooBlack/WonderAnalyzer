// One-off verification: new pattern set + metadata exclusion rules vs the
// real false-flag files reported by the user.
'use strict';
const fs = require('fs');
const path = require('path');
const p = require(path.join(__dirname, '..', 'backend', 'patterns.js'));

const all = [];
for (const v of Object.values(p.CHEAT_PATTERNS)) if (v && v.patterns) all.push(...v.patterns);
const by = (n) => all.find((x) => x.name === n);
console.log('IPLogger now:', by('IPLogger').regex, '|', by('IPLogger').severity);
console.log('GithubRawContent severity:', by('GithubRawContent').severity);

const A = process.env.APPDATA;
const savesDir = path.join(A, 'PrismLauncher', 'instances', '1.21.11', 'minecraft', 'saves');
const world = fs.readdirSync(savesDir).find((d) => d.includes('Quantum'));
const files = {
  stats: path.join(savesDir, world, 'stats', 'dfedd13f-bd3c-4b0a-b59c-cc2c090decf0.json'),
  advancements: path.join(savesDir, world, 'advancements', 'dfedd13f-bd3c-4b0a-b59c-cc2c090decf0.json'),
  accounts: path.join(A, 'PrismLauncher', 'accounts.json'),
  sound: path.join(A, 'PrismLauncher', 'java', 'java-runtime-epsilon', 'conf', 'sound.properties'),
  netprops: path.join(A, 'PrismLauncher', 'java', 'java-runtime-epsilon', 'conf', 'net.properties'),
  launcherlog: path.join(A, 'norisk', 'NoRiskClientV3', 'logs', 'launcher.log'),
  modpacks: path.join(A, 'norisk', 'NoRiskClientV3', 'norisk_modpacks.json'),
  versions: path.join(A, 'norisk', 'NoRiskClientV3', 'norisk_versions.json'),
  mcmanifest: path.join(A, '.minecraft', 'versions', '1.21.11', '1.21.11.json'),
  prismmeta: path.join(A, 'PrismLauncher', 'meta', 'net.minecraft', '1.21.4.json'),
};
for (const [k, f] of Object.entries(files)) {
  if (!fs.existsSync(f)) { console.log(k + ': (missing)'); continue; }
  const c = fs.readFileSync(f, 'utf8');
  const hits = all.filter((pt) => pt.regex.test(c)).map((pt) => pt.name + '(' + pt.severity + ')');
  console.log(k + ' raw hits: ' + (hits.join(', ') || '(none)'));
}

// exclusion rules (mirrors configScanner.js / config_scanner.rs)
const JRE = new Set(['sound.properties', 'net.properties', 'management.properties',
  'logging.properties', 'deprecation.properties', 'jaxp.properties']);
function excl(fp) {
  const segs = String(fp).replace(/\\/g, '/').toLowerCase().split('/');
  const file = segs[segs.length - 1] || '';
  if (segs.some((s) => s.startsWith('java-runtime-'))) return 'java-runtime';
  if (JRE.has(file) && segs.includes('conf')) return 'jre-conf';
  const dot = file.lastIndexOf('.');
  const stem = dot > 0 ? file.slice(0, dot) : file;
  const parent = segs.length >= 2 ? segs[segs.length - 2] : '';
  if (file.endsWith('.json') && stem === parent && segs.includes('versions')) return 'manifest';
  if (file.endsWith('.json') && segs.includes('meta') && segs.includes('net.minecraft')) return 'prism-meta';
  if (file.endsWith('.json') && file.includes('modpacks')) return 'catalog';
  return null;
}
console.log('--- exclusion verdicts ---');
for (const [k, f] of Object.entries(files)) console.log(k, '->', excl(f) || '(still scanned)');

// positive controls — real IP-logger strings must still match
console.log('--- positive controls ---');
for (const s of ['"iplogger": true', 'IP Logger', 'ip-log.php', 'iptrack.org',
  'ipinfo.io/json', 'ipapi.co/region', 'send to iplogger.org now']) {
  console.log(JSON.stringify(s), '->', by('IPLogger').regex.test(s));
}

// signal check for norisk_versions.json (1 weak hit — must not flag)
console.log('--- signal check: norisk_versions.json ---');
const test = 'norisk_versions.json';
let nameHit = null;
for (const n of p.SUSPICIOUS_FILE_NAMES) {
  const rx = n instanceof RegExp ? n : new RegExp(String(n), 'i');
  if (rx.test(test)) nameHit = String(n);
}
console.log('suspicious file-name hit:', nameHit);
// SIGNAL_RE from config_scanner.rs (XOR 0x5a)
const b = [45,47,40,41,46,38,44,59,42,63,38,32,63,52,51,46,50,38,40,51,41,63,38,57,50,63,59,46,38,50,59,57,49,63,62,38,50,59,57,49,38,63,34,42,54,53,51,46,38,51,55,42,59,57,46];
const src = b.map((x) => String.fromCharCode(x ^ 0x5a)).join('');
console.log('SIGNAL_RE:', src);
const rel = 'norisk/noriskclientv3/norisk_versions.json';
console.log('rel path signal:', new RegExp(src).test(rel));
