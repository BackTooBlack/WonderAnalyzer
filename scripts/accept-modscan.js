/**
 * Real instance-mods acceptance:
 *   MUST    : vmp jar flagged critical with >=5 Zelix markers; echoclient
 *             flagged; known-legit manifests (sodium/lithium/...) never
 *             threat-flagged; module-info.class never causes a flag.
 *   REPORT  : full verdict list for manual review.
 *
 * Usage: node scripts/accept-modscan.js <modscan.json>
 */
const fs = require('fs');
const r = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const results = r.results || [];
const summary = r.summary || {};
const bad = [];
const norm = (x) => String(x).replace(/\\/g, '/');

console.log(`summary: ${JSON.stringify(summary)}`);
console.log('--- verdicts ---');
for (const f of results) {
  const obf = f.obfuscationAnalysis || {};
  console.log('  ', String(f.threatLevel).toUpperCase().padEnd(11), norm(f.name),
    'score=' + f.threatScore,
    f.verified ? '[verified]' : '',
    obf.isObfuscated ? `[obf ${obf.score} zelix=${obf.zelixMarkers || 0}]` : '');
}

// ===== MUST =====
const vmp = results.find((f) => /(^|\/)vmp[^/]*\.jar$/i.test(norm(f.name)));
if (!vmp) bad.push('MISSING vmp jar');
else {
  const obf = vmp.obfuscationAnalysis || {};
  if ((obf.zelixMarkers || 0) < 5) bad.push(`vmp zelixMarkers=${obf.zelixMarkers} expected >=5`);
  if (!obf.isObfuscated) bad.push('vmp not obfuscated');
  if (vmp.threatLevel !== 'critical') bad.push(`vmp level=${vmp.threatLevel} expected critical`);
}

const echo = results.find((f) => /echoclient[^/]*\.jar$/i.test(norm(f.name)));
if (!echo) bad.push('MISSING echoclient jar');
else if (echo.threatLevel !== 'critical') bad.push(`echoclient level=${echo.threatLevel} expected critical`);

// Known-legit manifest ids must never be threat-flagged (verified OR clean).
const LEGIT_IDS = new Set([
  'sodium', 'lithium', 'iris', 'iris-neoforge', 'fabric-api', 'fabricloader',
  'cloth-config', 'modmenu', 'jei', 'architectury-api', 'create', 'ferritecore',
  'entityculling', 'indium', 'replaymod', 'xaerominimap', 'xaeroworldmap',
  'smoothboot', 'nvidium', 'moreculling', 'lambdynlights', 'cloth-config4',
]);
for (const f of results) {
  if (f.threatLevel === 'info') continue;
  const id = (f.modId || '').toLowerCase();
  if (LEGIT_IDS.has(id)) {
    const zelix = f.obfuscationAnalysis && f.obfuscationAnalysis.zelixMarkers >= 5;
    if (!zelix && f.threatLevel !== 'safe') {
      bad.push(`LEGIT FLAGGED: ${norm(f.name)} id=${id} level=${f.threatLevel} score=${f.threatScore}`);
    }
  }
  // module-info.class must never be the reason for a flag
  const mi = (f.fileMatches || []).find((m) => /module-info/i.test(String(m.file || m.name || '')));
  if (mi) bad.push(`module-info caused flag: ${norm(f.name)}`);
}

const flagged = results.filter((f) => f.threatLevel !== 'safe' && f.threatLevel !== 'info');
const safe = results.filter((f) => f.threatLevel === 'safe');
console.log(`safe=${safe.length} flagged=${flagged.length} total=${results.length}`);
console.log('flagged:');
for (const f of flagged) console.log('  *', norm(f.name), '→', f.threatLevel, f.threatScore);

console.log(bad.length ? 'FAIL: ' + bad.join('; ') : 'E2E_REAL_MODS_PASS');
process.exit(bad.length ? 1 : 0);
