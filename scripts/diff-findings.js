// Diff non-info findings between two config-scan JSON outputs.
'use strict';
const fs = require('fs');
const load = (f) => JSON.parse(fs.readFileSync(f, 'utf8')).results
  .filter((r) => r.threatLevel !== 'info')
  .map((r) => ({ k: r.name.replace(/\\/g, '/'), l: r.threatLevel }));
const oldL = load(process.argv[2]);
const newL = load(process.argv[3]);
const oldK = new Set(oldL.map((x) => x.k));
const newK = new Set(newL.map((x) => x.k));
console.log('old flagged:', oldL.length, ' new flagged:', newL.length);
console.log('--- GONE (fixed):');
for (const x of oldL) if (!newK.has(x.k)) console.log('  -', x.k, '(', x.l, ')');
console.log('--- NEW (regression check):');
for (const x of newL) if (!oldK.has(x.k)) console.log('  +', x.k, '(', x.l, ')');
