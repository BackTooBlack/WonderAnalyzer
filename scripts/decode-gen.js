// Debug helper: decode PatternDef entries from patterns_gen.rs
'use strict';
const fs = require('fs');
const path = require('path');
const K = 0x5a;
const src = fs.readFileSync(path.join(__dirname, '..', 'src-tauri', 'src', 'patterns_gen.rs'), 'utf8');
const dec = (s) => s.split(',').map((n) => String.fromCharCode((+n.trim()) ^ K)).join('');
const blocks = src.split('PatternDef {').slice(1);
const want = process.argv.slice(2);
let out = [];
for (const b of blocks) {
  const nm = /name: &\[([^\]]*)\]/.exec(b);
  const so = /source: &\[([^\]]*)\]/.exec(b);
  const sev = /severity: "(\w+)"/.exec(b);
  if (!nm) continue;
  const name = dec(nm[1]);
  if (want.length === 0 || want.some((w) => name.toLowerCase().includes(w.toLowerCase()))) {
    out.push(`${name} | sev=${sev && sev[1]} | regex=${so ? dec(so[1]) : '?'}`);
  }
}
console.log(out.join('\n') || '(no matches)');
