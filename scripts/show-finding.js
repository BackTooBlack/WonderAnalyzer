// Usage: node scripts/show-finding.js <scan.json> <name-substring>
'use strict';
const fs = require('fs');
const [, , file, needle] = process.argv;
const d = JSON.parse(fs.readFileSync(file, 'utf8'));
const norm = (s) => String(s).split('\\').join('/');
let found = 0;
for (const r of d.results) {
  if (norm(r.name).toLowerCase().includes(String(needle).toLowerCase())) {
    found++;
    console.log('=== ' + norm(r.name) + ' | ' + r.threatLevel + ' score=' + r.threatScore);
    for (const ms of Object.values(r.categories || {})) {
      for (const m of ms) console.log('  [' + m.severity + '] ' + m.name + ' :: ' + JSON.stringify(m.context).slice(0, 240));
    }
  }
}
if (!found) console.log('(no finding matching ' + needle + ')');
