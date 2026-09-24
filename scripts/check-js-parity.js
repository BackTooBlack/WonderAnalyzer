/**
 * JS-parity check: drives the legacy Electron ConfigScanner (backend/) over
 * the same fixture as the Rust E2E and asserts the shared rules hold:
 * artifacts, verified-client trust, diagnostic crash reports, weak/strong
 * gate, bare module keys, optimizer mentions, mods-dir skip.
 *
 * Usage: node scripts/check-js-parity.js <fixtureRoot>
 */
const path = require('path');
const { ConfigScanner } = require(path.join(__dirname, '..', 'backend', 'configScanner'));

const root = process.argv[2];
if (!root) {
  console.error('usage: node scripts/check-js-parity.js <fixtureRoot>');
  process.exit(2);
}

const mockWebContents = { send() {}, isDestroyed() { return false; } };

(async () => {
  const scanner = new ConfigScanner(mockWebContents);
  const out = await scanner.scan(root);
  const results = out.results || [];
  const s = out.summary;
  const bad = [];
  const norm = (x) => String(x).replace(/\\/g, '/');
  const names = results.map((f) => norm(f.name));
  const find = (n) => results.find((f) => norm(f.name) === n);

  console.log(`launchers=${JSON.stringify(s.launchers)} indexed:${s.indexed} analyzed:${s.analyzed} found:${s.found} critical:${s.critical} warning:${s.warning} opt:${s.optimizers} art:${s.artifacts} cli:${s.clients}`);

  // ===== artifacts =====
  for (const n of ['zenith-macros', '.vapeclient', 'zenith-macros.exe']) {
    const f = find(n);
    if (!f) bad.push('MISSING artifact ' + n);
    else if (f.threatLevel !== 'critical' || f.modId !== 'artifact') bad.push(n + ' not critical/artifact');
  }
  const cache = find('.vapeclient/cache');
  if (!cache || cache.threatLevel !== 'critical' || cache.modId !== 'artifact') bad.push('vape cache not critical artifact');
  const zprof = find('zenith-macros/profiles.json');
  if (!zprof || zprof.threatLevel !== 'critical' || zprof.modId !== 'artifact') bad.push('zenith profiles not critical artifact');

  // ===== contexts =====
  const crash = results.find((f) => norm(f.name).includes('crash-2026-09-23'));
  if (crash && (crash.threatLevel !== 'info' || crash.modId !== 'report')) bad.push('crash report must be info/report');
  const feather = find('.feather/modules.json');
  if (!feather || feather.threatLevel !== 'info' || feather.modId !== 'client') bad.push('feather must be info/client');
  const opt = results.find((f) => f.threatLevel === 'info' && f.modId === 'optimizer');
  if (!opt) bad.push('optimizer mention missing');

  // ===== detections =====
  const ka = find('.minecraft/config/killaura.config');
  if (!ka || ka.threatLevel !== 'critical') bad.push('killaura.config must be critical');
  if (ka && ka.threatScore !== 60) bad.push(`killaura score=${ka.threatScore} expected 60`);
  const mods = find('.minecraft/config/modules.json');
  if (!mods || mods.threatLevel !== 'critical') bad.push('modules.json must be critical');
  const scaffold = find('.minecraft/config/scaffold-helper.txt');
  if (!scaffold || scaffold.threatLevel !== 'warning') bad.push('scaffold-helper must be warning (bare key)');
  if (scaffold && scaffold.threatScore !== 32) bad.push(`scaffold score=${scaffold.threatScore} expected 32`);
  const log = find('.minecraft/logs/latest.log');
  if (!log || log.threatLevel !== 'critical' || !String(log.modLoader).startsWith('Cheat Log')) bad.push('latest.log must be Cheat Log critical');

  // ===== must not flag =====
  const mustNot = [
    'NotALauncher/cheat.txt',
    '.minecraft/config/qol-settings.json',
    '.minecraft/config/inventorysorter.cfg',
    '.minecraft/options.txt',
    '.minecraft/launcher_profiles.json',
    'PrismLauncher/prismlauncher.cfg',
    'PrismLauncher/instances/vanilla/autoSprint.txt',
    '.minecraft/mods/scan.log',
    '.minecraft/mods/PrecisionScan-x/scan.log',
    '.minecraft/mods/PrecisionScan-x/report.txt',
  ];
  for (const n of mustNot) if (names.includes(n)) bad.push('FALSE-POSITIVE ' + n);

  // ===== summary counts (JS skips jars: 15 analyzed, 9 found, 8 critical) =====
  if (s.launchers.length !== 3) bad.push(`launchers=${s.launchers.length} expected 3`);
  if (s.analyzed !== 15) bad.push(`analyzed=${s.analyzed} expected 15`);
  if (s.found !== 9) bad.push(`found=${s.found} expected 9`);
  if (s.critical !== 8) bad.push(`critical=${s.critical} expected 8`);
  if (s.warning !== 1) bad.push(`warning=${s.warning} expected 1`);
  if (s.optimizers !== 1) bad.push(`optimizers=${s.optimizers} expected 1`);
  if (s.artifacts !== 5) bad.push(`artifacts=${s.artifacts} expected 5`);
  if (s.clients !== 1) bad.push(`clients=${s.clients} expected 1`);

  console.log(bad.length ? 'FAIL: ' + bad.join('; ') : 'JS_PARITY_PASS');
  process.exit(bad.length ? 1 : 0);
})().catch((e) => {
  console.error('FAIL: ' + e.message);
  process.exit(1);
});
