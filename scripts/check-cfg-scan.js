const fs = require('fs');
const r = JSON.parse(fs.readFileSync(process.argv[2] || '/tmp/cfgscan.json', 'utf8'));
const s = r.summary;
console.log('launchers:', JSON.stringify(s.launchers));
console.log(`indexed:${s.indexed} analyzed:${s.analyzed} found:${s.found} critical:${s.critical} warning:${s.warning}`);
for (const f of r.results) console.log('  ', f.threatLevel.toUpperCase().padEnd(10), f.name, 'score=' + f.threatScore);

const names = r.results.map((f) => f.name.replace(/\\/g, '/'));
const bad = [];
const mustFlag = [
  '.minecraft/config/killaura.config',
  '.minecraft/config/modules.json',
  '.minecraft/config/scaffold-helper.txt',
];
const mustNotFlag = [
  'NotALauncher/cheat.txt',          // outside a launcher folder
  '.minecraft/config/qol-settings.json', // single weak QoL signature
  '.minecraft/config/inventorysorter.cfg',
  '.minecraft/options.txt',          // vanilla
  'PrismLauncher/instances/vanilla/autoSprint.txt', // single weak
  '.minecraft/launcher_profiles.json',
  'PrismLauncher/prismlauncher.cfg',
];
for (const n of mustFlag) if (!names.includes(n)) bad.push('MISSING ' + n);
for (const n of mustNotFlag) if (names.includes(n)) bad.push('FALSE-POSITIVE ' + n);
if (s.found !== mustFlag.length) bad.push(`found=${s.found} expected=${mustFlag.length}`);
if (s.launchers.length !== 2) bad.push(`launchers=${s.launchers.length} expected 2`);
if (s.analyzed !== 9) bad.push(`analyzed=${s.analyzed} expected 9 (non-launcher file must not be read)`);
const ka = r.results.find((f) => f.name.includes('killaura.config'));
if (!ka || ka.threatLevel !== 'critical') bad.push('killaura.config must be CRITICAL');

console.log(bad.length ? 'FAIL: ' + bad.join('; ') : 'E2E_CONFIG_SCAN_PASS');
process.exit(bad.length ? 1 : 0);
