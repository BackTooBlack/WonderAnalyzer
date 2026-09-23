const fs = require('fs');
const r = JSON.parse(fs.readFileSync(process.argv[2] || '/tmp/cfgscan.json', 'utf8'));
const s = r.summary;
console.log('launchers:', JSON.stringify(s.launchers));
console.log(`indexed:${s.indexed} analyzed:${s.analyzed} found:${s.found} critical:${s.critical} warning:${s.warning} optimizers:${s.optimizers}`);
for (const f of r.results) console.log('  ', f.threatLevel.toUpperCase().padEnd(10), f.name, 'score=' + f.threatScore, '|', f.modLoader);

const names = r.results.map((f) => f.name.replace(/\\/g, '/'));
const bad = [];
const mustFlag = [
  '.minecraft/config/killaura.config',
  '.minecraft/config/modules.json',
  '.minecraft/config/scaffold-helper.txt',
  '.minecraft/logs/latest.log',            // log scanning: cheat module evidence
];
const mustNotFlag = [
  'NotALauncher/cheat.txt',          // outside a launcher folder
  '.minecraft/config/qol-settings.json', // single weak QoL signature
  '.minecraft/config/inventorysorter.cfg',
  '.minecraft/options.txt',          // vanilla
  'PrismLauncher/instances/vanilla/autoSprint.txt', // single weak
  '.minecraft/launcher_profiles.json',
  'PrismLauncher/prismlauncher.cfg',
  // NOTE: marlows-crystal-optimizer.cfg IS expected in results — but as an
  // info mention (asserted below), and excluded from summary.found.
];
for (const n of mustFlag) if (!names.includes(n)) bad.push('MISSING ' + n);
for (const n of mustNotFlag) if (names.includes(n)) bad.push('FALSE-POSITIVE ' + n);
if (s.found !== mustFlag.length) bad.push(`found=${s.found} expected=${mustFlag.length}`);
if (s.launchers.length !== 2) bad.push(`launchers=${s.launchers.length} expected 2`);
if (s.analyzed !== 11) bad.push(`analyzed=${s.analyzed} expected 11 (9 configs + optimizer cfg + log)`);
if (s.optimizers !== 1) bad.push(`optimizers=${s.optimizers} expected 1`);

const ka = r.results.find((f) => f.name.includes('killaura.config'));
if (!ka || ka.threatLevel !== 'critical') bad.push('killaura.config must be CRITICAL');

// Log evidence must be flagged as a log, with a real threat level
const log = r.results.find((f) => f.name.replace(/\\/g, '/') === '.minecraft/logs/latest.log');
if (!log) bad.push('latest.log missing');
else {
  if (log.threatLevel !== 'critical') bad.push(`latest.log threatLevel=${log.threatLevel} expected critical`);
  if (!String(log.modLoader).startsWith('Cheat Log')) bad.push(`latest.log must be labeled Cheat Log, got ${log.modLoader}`);
}

// Optimizer must be an INFO mention carrying the optimizer's name
const opt = r.results.find((f) => f.threatLevel === 'info');
if (!opt) bad.push('optimizer info mention missing');
else {
  if (!String(opt.modLoader).includes('Marlow')) bad.push(`optimizer mention must name the optimizer, got ${opt.modLoader}`);
  if (opt.threatScore !== 0) bad.push(`optimizer threatScore=${opt.threatScore} expected 0`);
  if (opt.name.replace(/\\/g, '/') !== '.minecraft/config/marlows-crystal-optimizer.cfg') bad.push('unexpected info entry: ' + opt.name);
}

console.log(bad.length ? 'FAIL: ' + bad.join('; ') : 'E2E_CONFIG_SCAN_PASS');
process.exit(bad.length ? 1 : 0);
