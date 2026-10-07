#!/usr/bin/env node
// VirusTotal string-leak audit for a shipped binary.
//
// All detection vocabulary (malware rule regexes, rule names, cheat-module
// keys, artifact regexes, pattern names/sources) lives in the Rust sources
// as XOR-encoded byte arrays (PATTERN_XOR_KEY = 0x5a) and is decoded at
// runtime by malware::decode(). This audit re-derives every such string
// from the source arrays and verifies NONE of them appears as plaintext in
// the exe — i.e. the encoding (and the black_box decode path) survived the
// build. Also checks a curated list of terms that historically triggered
// AV string heuristics (Heur:Ransom/..., Trapmine ML).
//
// Usage: node tools/audit-vt-strings.js <exe>
// Exit 0 = no leaks; exit 1 = leak (or parse failure); exit 2 = usage.

'use strict';

const fs = require('fs');
const path = require('path');

const XOR_KEY = 0x5a;
const SRC_DIR = path.join(__dirname, '..', 'src-tauri', 'src');

// Historically VT-flagged vocabulary: must never appear in the binary.
const CURATED_VT_TERMS = [
  'ransom', 'clipper', 'wallet', 'keylog', 'killaura', 'aristois',
  'scaffold', 'wurst', 'bleachhack', 'klassmaster', 'hacked', 'zenith',
];

const exePath = process.argv[2];
if (!exePath) {
  console.error('usage: node tools/audit-vt-strings.js <exe>');
  process.exit(2);
}

// Generic words that legitimately occur in ANY build of this app (UI text,
// docs strings, error messages) even though they also occur inside encoded
// rule vocabulary. Everything else that decodes from a signature table and
// is found plaintext in the exe is a leak.
//   "module" — English word in by-design plaintext only: report templates
//              ("Cheat module evidence in game log"), the Rust std error
//              "(This is a module invariant.)" and the OpenSSL asm comment
//              "AES-NI GCM module for x86_64". Never as a pattern name.
const WORD_ALLOWLIST = new Set([
  'malware', 'critical', 'suspicious', 'warning', 'config', 'version',
  'module',
]);

function decode(bytes) {
  return Buffer.from(bytes.map((b) => b ^ XOR_KEY));
}

function isPrintable(buf) {
  for (const b of buf) {
    if (b < 0x20 || b > 0x7e) return false;
  }
  return true;
}

// Pull every `&[n,n,...]` numeric byte-array literal out of the sources.
function extractVocabulary() {
  const terms = new Map(); // decoded string -> source file
  for (const f of fs.readdirSync(SRC_DIR)) {
    if (!f.endsWith('.rs')) continue;
    const text = fs.readFileSync(path.join(SRC_DIR, f), 'utf8');
    const re = /&\[((?:\d{1,3},){5,}\d{1,3})\]/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const nums = m[1].split(',').map(Number);
      if (nums.some((n) => n > 255)) continue;
      const dec = decode(nums);
      if (dec.length < 6 || !isPrintable(dec)) continue;
      const s = dec.toString('latin1');
      if (!terms.has(s)) terms.set(s, f);
    }
  }
  return terms;
}

// Find `term` in `buf` only at word boundaries: raw substring hits inside
// longer words/identifiers ("SystemInfo" in "GetSystemInfo",
// "exploit" in "exploitation") are not leaks of the vocabulary itself.
function findWord(buf, term) {
  const t = Buffer.from(term, 'latin1');
  const isWordByte = (b) =>
    b !== undefined &&
    ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) ||
      (b >= 0x61 && b <= 0x7a) || b === 0x5f);
  let i = -1;
  while ((i = buf.indexOf(t, i + 1)) !== -1) {
    if (!isWordByte(buf[i - 1]) && !isWordByte(buf[i + t.length])) return i;
  }
  return -1;
}

function main() {
  const exe = fs.readFileSync(exePath);
  const vocab = extractVocabulary();
  if (vocab.size === 0) {
    console.error('VT_AUDIT_FAIL: decoded 0 vocabulary strings from sources — extractor broken');
    process.exit(1);
  }

  const leaks = [];
  for (const [term, src] of vocab) {
    if (WORD_ALLOWLIST.has(term.toLowerCase())) continue;
    if (findWord(exe, term) !== -1) {
      leaks.push({ term, src, kind: 'table' });
    }
  }
  // Curated terms are matched raw (substring): any occurrence is a leak.
  for (const term of CURATED_VT_TERMS) {
    if (exe.includes(Buffer.from(term, 'latin1'))) {
      leaks.push({ term, src: 'curated', kind: 'curated' });
    }
  }

  console.log(`exe:    ${exePath} (${exe.length} bytes)`);
  console.log(`vocab:  ${vocab.size} decoded signature strings checked (${WORD_ALLOWLIST.size} generic words allowlisted)`);
  if (leaks.length) {
    for (const l of leaks) console.error(`VT_AUDIT_FAIL: plaintext "${l.term}" (${l.kind}, from ${l.src})`);
    process.exit(1);
  }
  console.log('VT_AUDIT_PASS');
}

main();
