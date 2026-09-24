// E2E checker for --scan-config output against the make-fixture.js tree.
// Usage: node scripts/check-cfg-scan.js <path-to-scan.json>
const fs = require('fs');
const r = JSON.parse(fs.readFileSync(process.argv[2] || '/tmp/cfgscan.json', 'utf8'));
const s = r.summary;
console.log('launchers:', JSON.stringify(s.launchers));
console.log(`indexed:${s.indexed} analyzed:${s.analyzed} found:${s.found} critical:${s.critical} warning:${s.warning} optimizers:${s.optimizers} artifacts:${s.artifacts} clients:${s.clients}`);
for (const f of r.results) console.log('  ', String(f.threatLevel).toUpperCase().padEnd(10), f.name.replace(/\\/g, '/'), 'score=' + f.threatScore, '|', f.modLoader);

const norm = (x) => String(x).replace(/\\/g, '/');
const names = r.results.map((f) => norm(f.name));
const bad = [];

// ===== must be flagged =====
const mustFlag = {
  '.minecraft/config/killaura.config': 'critical',
  '.minecraft/config/modules.json': 'critical',
  '.minecraft/config/scaffold-helper.txt': 'warning',
  '.minecraft/logs/latest.log': 'critical',
  'zenith-macros/profiles.json': 'critical',
  '.vapeclient/cache': 'critical',
  'zenith-macros': 'critical',            // artifact folder finding
  '.vapeclient': 'critical',              // artifact folder finding
  'zenith-macros.exe': 'critical',        // root-level cheat exe
};
for (const [n, lvl] of Object.entries(mustFlag)) {
  const f = r.results.find((x) => norm(x.name) === n);
  if (!f) { bad.push('MISSING ' + n); continue; }
  if (f.threatLevel !== lvl) bad.push(`${n} level=${f.threatLevel} expected ${lvl}`);
}

// ===== must NOT be flagged at all =====
const mustNotFlag = [
  'NotALauncher/cheat.txt',
  '.minecraft/config/qol-settings.json',
  '.minecraft/config/inventorysorter.cfg',
  '.minecraft/options.txt',
  '.minecraft/launcher_profiles.json',
  'PrismLauncher/prismlauncher.cfg',
  'PrismLauncher/instances/vanilla/autoSprint.txt',
  '.minecraft/mods/scan.log',                    // mods-dir text never read
  '.minecraft/mods/PrecisionScan-x/scan.log',    // report folder never read
  '.minecraft/mods/PrecisionScan-x/report.txt',
  '.minecraft/mods/legit-lib.jar',
  '.minecraft/mods/cheat-zkm.jar',               // jars are never opened here
  '.minecraft/mods/echoclient-1.0.jar',          // (jar analysis = mod scanner)
];
for (const n of mustNotFlag) if (names.includes(n)) bad.push('FALSE-POSITIVE ' + n);

// ===== context rules =====
const infoEntries = r.results.filter((f) => f.threatLevel === 'info');

// Crash report: mention at most, never a threat
const crash = r.results.find((f) => norm(f.name).includes('crash-2026-09-23'));
if (crash) {
  if (crash.threatLevel !== 'info' || crash.modId !== 'report' || crash.threatScore !== 0) {
    bad.push(`crash report must be info/report/0, got ${crash.threatLevel}/${crash.modId}/${crash.threatScore}`);
  }
}

// Feather: official-client mention only
const feather = r.results.find((f) => norm(f.name) === '.feather/modules.json');
if (!feather) bad.push('feather modules.json missing (expected mention)');
else {
  if (feather.threatLevel !== 'info' || feather.modId !== 'client') bad.push('feather must be info/client');
  if (!String(feather.modLoader).includes('Feather')) bad.push('feather label must name the client');
  if (feather.threatScore !== 0) bad.push('feather threatScore must be 0');
}

// Optimizer: info mention naming the optimizer
const opt = infoEntries.find((f) => f.modId === 'optimizer');
if (!opt) bad.push('optimizer info mention missing');
else {
  if (!String(opt.modLoader).includes('Marlow')) bad.push('optimizer mention must name the optimizer');
  if (opt.threatScore !== 0) bad.push('optimizer threatScore must be 0');
}

// Jars: the %APPDATA% scanner must never open or report a .jar
const jars = r.results.filter((f) => norm(f.name).endsWith('.jar'));
if (jars.length) bad.push('jar findings present: ' + jars.map((f) => norm(f.name)).join(', '));

// killaura scoring contract from the original E2E
const ka = r.results.find((f) => norm(f.name) === '.minecraft/config/killaura.config');
if (ka && ka.threatScore !== 60) bad.push(`killaura score=${ka.threatScore} expected 60`);

// ===== summary consistency =====
const foundExpected = Object.keys(mustFlag).length;
if (s.found !== foundExpected) bad.push(`found=${s.found} expected=${foundExpected}`);
if (s.launchers.length !== 3) bad.push(`launchers=${s.launchers.length} expected 3`);
if (s.analyzed !== 15) bad.push(`analyzed=${s.analyzed} expected 15`);
if (s.indexed !== 15) bad.push(`indexed=${s.indexed} expected 15`);
if (s.critical !== 8) bad.push(`critical=${s.critical} expected 8`);
if (s.warning !== 1) bad.push(`warning=${s.warning} expected 1`);
if (s.optimizers !== 1) bad.push(`optimizers=${s.optimizers} expected 1`);
if (s.artifacts !== 5) bad.push(`artifacts=${s.artifacts} expected 5 (2 folders + exe + 2 files)`);
if (s.clients !== 1) bad.push(`clients=${s.clients} expected 1`);
if (infoEntries.length !== 3) bad.push(`info entries=${infoEntries.length} expected 3`);

console.log(bad.length ? 'FAIL: ' + bad.join('; ') : 'E2E_CONFIG_SCAN_PASS');
process.exit(bad.length ? 1 : 0);
