/**
 * Real-%APPDATA% acceptance — asserts the user-facing contract on the
 * real machine (not the fixture):
 *   MUST FIND : zenith-macros + .vapeclient artifact folders.
 *   MUST NOT  : any .jar finding — jars are never opened by this scanner
 *               (jar analysis lives in the mod scanner).
 *   MUST NOT  : threat-flag anything under crash-reports/, .feather/,
 *               sentry/, PrecisionScan*, mod-forensics*, Local/Session
 *               Storage — mentions (info) or nothing at all.
 *   SOFT      : killaura.config / latest.log presence (reported, not fatal).
 *
 * Usage: node scripts/accept-appdata.js <cfgscan.json>
 */
const fs = require('fs');
const r = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const s = r.summary;
const results = r.results || [];
const bad = [];
const norm = (x) => String(x).replace(/\\/g, '/');

console.log(`launchers(${s.launchers.length}): ${JSON.stringify(s.launchers)}`);
console.log(`indexed:${s.indexed} analyzed:${s.analyzed} found:${s.found} critical:${s.critical} warning:${s.warning} opt:${s.optimizers} art:${s.artifacts} cli:${s.clients}`);
console.log('--- findings ---');
for (const f of results) {
  console.log('  ', String(f.threatLevel).toUpperCase().padEnd(10), norm(f.name), 'score=' + f.threatScore, '|', f.modLoader,
    f.obfuscationAnalysis && f.obfuscationAnalysis.zelixMarkers ? `| zelix=${f.obfuscationAnalysis.zelixMarkers}` : '');
}

// ===== MUST FIND =====
const dirZen = results.find((f) => norm(f.name) === 'zenith-macros');
if (!dirZen) bad.push('MISSING zenith-macros artifact folder finding');
else if (dirZen.threatLevel !== 'critical' || dirZen.modId !== 'artifact') bad.push('zenith-macros not critical/artifact');

const dirVape = results.find((f) => norm(f.name) === '.vapeclient');
if (!dirVape) bad.push('MISSING .vapeclient artifact folder finding');
else if (dirVape.threatLevel !== 'critical' || dirVape.modId !== 'artifact') bad.push('.vapeclient not critical/artifact');

// jars must never be opened or reported by the %APPDATA% scanner
const jars = results.filter((f) => norm(f.name).endsWith('.jar'));
if (jars.length) bad.push('jar findings present (jars must be skipped): ' + jars.map((f) => norm(f.name)).join(', '));

// ===== MUST NOT THREAT =====
const NEVER_THREATEN = [
  /crash-reports\//i,
  /\.feather\//i,
  /(^|\/)sentry\//i,
  /precisionscan/i,
  /mod-forensics/i,
  /forensics-report/i,
  /local storage\//i,
  /session storage\//i,
];
for (const f of results) {
  const n = norm(f.name);
  if (NEVER_THREATEN.some((re) => re.test(n)) && f.threatLevel !== 'info') {
    bad.push(`FALSE-THREAT ${n} (${f.threatLevel})`);
  }
}

// ===== SOFT checks =====
const soft = [];
if (!results.some((f) => norm(f.name).endsWith('killaura.config'))) soft.push('killaura.config not present (ok if user has none)');
if (!results.some((f) => norm(f.name).endsWith('.minecraft/logs/latest.log'))) soft.push('latest.log not flagged (ok if log is clean)');
const infoCount = results.filter((f) => f.threatLevel === 'info').length;
console.log(`info mentions: ${infoCount} | soft: ${soft.length ? soft.join(' | ') : 'none'}`);

// ===== verdict list for manual review =====
const flagged = results.filter((f) => f.threatLevel !== 'info');
console.log(`flagged (${flagged.length}):`);
for (const f of flagged) console.log('  *', norm(f.name), '→', f.threatLevel, f.threatScore);

console.log(bad.length ? 'FAIL: ' + bad.join('; ') : 'E2E_REAL_APPDATA_PASS');
process.exit(bad.length ? 1 : 0);
