/**
 * VirusTotal hardening for the signature tables that live directly in the
 * Rust sources (the big pattern database is handled by tools/gen-patterns.js
 * -> patterns_gen.rs).
 *
 * Every detection-vocabulary string — malware-rule regex sources, rule
 * names, finding types, cheat-module key lists, the artifact exe/folder
 * regexes and the Zelix obfuscator markers — is rewritten in place as a
 * XOR-encoded byte array (PATTERN_XOR_KEY = 0x5a) and decoded once at init
 * by malware::decode(), so none of it appears verbatim inside the shipped
 * executable. AV string heuristics (Heur:Ransom/..., Trapmine ML) key on
 * exactly this kind of plaintext signature blob.
 *
 * Usage:  node tools/encode-signatures.js
 * Idempotent: blocks that are already encoded are reported as skipped.
 * After restoring a table to plaintext by hand, re-run this script.
 */
const fs = require('fs');
const path = require('path');

const XOR_KEY = 0x5a;
const SRC_DIR = path.join(__dirname, '..', 'src-tauri', 'src');
const summary = [];

function enc(s) {
  const bytes = Array.from(Buffer.from(s, 'utf8'), (b) => (b ^ XOR_KEY));
  return '[' + bytes.join(',') + ']';
}

function unescape(s) {
  return s.replace(/\\(.)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
}

function edit(file, fn) {
  const p = path.join(SRC_DIR, file);
  const before = fs.readFileSync(p, 'utf8');
  const after = fn(before);
  if (after !== before) fs.writeFileSync(p, after);
}

// ===== 1. `const NAME: &[&str] = &[ ... ];` string-list tables =====
function encodeStringList(text, varName) {
  const marker = `const ${varName}: &[&str] = &[`;
  const i = text.indexOf(marker);
  if (i < 0) return [text, `${varName}: already encoded/missing`];
  const end = text.indexOf('\n];', i);
  if (end < 0) throw new Error(`${varName}: closing ]; not found`);
  const block = text.slice(i, end + '\n];'.length);
  const strings = [...block.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => unescape(m[1]));
  if (strings.length === 0) throw new Error(`${varName}: no strings found`);
  const pub = text.slice(Math.max(0, i - 4), i) === 'pub ';
  const p = pub ? 'pub ' : '';
  const entries = strings.map((s) => `    &${enc(s)},`).join('\n');
  const replacement =
    `const ${varName}_SRC: &[&[u8]] = &[\n${entries}\n];\n` +
    `${p}static ${varName}: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {\n` +
    `    ${varName}_SRC.iter().map(|b| crate::malware::decode(b)).collect()\n` +
    `});`;
  return [text.slice(0, i) + replacement + text.slice(end + '\n];'.length), `${varName}: ${strings.length} strings`];
}

// ===== 2. `const NAME: &str = r"...";` regex-source constants =====
function encodeConstRegex(text, varName) {
  const marker = `const ${varName}: &str = `;
  const i = text.indexOf(marker);
  if (i < 0) return [text, `${varName}: already encoded/missing`];
  const m = /r"([^"]*)"/.exec(text.slice(i));
  if (!m || m.index > 300) throw new Error(`${varName}: raw string not found`);
  const litStart = i + m.index;
  const litEnd = litStart + m[0].length;
  if (text[litEnd] !== ';') throw new Error(`${varName}: unexpected literal end: ${JSON.stringify(text.slice(litEnd, litEnd + 4))}`);
  const replacement = `const ${varName}_SRC: &[u8] = &${enc(m[1])};`;
  return [text.slice(0, i) + replacement + text.slice(litEnd + 1), `${varName}: regex`];
}

// ===== 3. `Regex::new(r"...")` inside a `static NAME: ...LazyLock<Regex>` =====
function encodeStaticRegex(text, varName) {
  const anchor = text.indexOf(`static ${varName}:`);
  if (anchor < 0) return [text, `${varName}: missing`];
  const window = text.slice(anchor, anchor + 600);
  const m = /Regex::new\(\s*r"([^"]*)"\s*,?\s*\)/.exec(window);
  if (!m) return [text, `${varName}: skipped (already encoded or pattern not matched)`];
  const at = anchor + m.index;
  const replacement = `Regex::new(&crate::malware::decode(&${enc(m[1])}))`;
  return [text.slice(0, at) + replacement + text.slice(at + m[0].length), `${varName}: regex`];
}

// ===== 4. the malware-rule table in scanner.rs =====
const DEFS_PLAIN = 'let defs: &[(&str, bool, &str, &str, &str)] = &[';
const DEFS_ENC = "let defs: &[(&[u8], bool, &[u8], &'static str, &[u8])] = &[";

function encodeMalwareRules(text) {
  const i = text.indexOf(DEFS_PLAIN);
  if (i < 0) return [text, 'MALWARE_RULES: already encoded/missing'];
  const end = text.indexOf('\n    ];', i);
  if (end < 0) throw new Error('MALWARE_RULES: closing ]; not found');
  const body = text.slice(i + DEFS_PLAIN.length, end);

  const lines = body.split('\n').map((line) => {
    const t = line.trim();
    if (t === '' || t.startsWith('//')) return line;
    if (!t.startsWith('(') || !t.endsWith('),')) throw new Error(`unexpected rule line: ${line}`);

    const inner = t.slice(1, -2); // strip "(" and "),"
    let src;
    let rest;
    if (inner.startsWith('r#"')) {
      const close = inner.indexOf('"#', 3);
      if (close < 0) throw new Error(`unterminated raw string: ${line}`);
      src = inner.slice(3, close);
      rest = inner.slice(close + 2);
    } else if (inner.startsWith('r"')) {
      const close = inner.indexOf('"', 2);
      if (close < 0) throw new Error(`unterminated raw string: ${line}`);
      src = inner.slice(2, close);
      rest = inner.slice(close + 1);
    } else if (inner.startsWith('"')) {
      const m = /^"((?:[^"\\]|\\.)*)"([\s\S]*)$/.exec(inner);
      if (!m) throw new Error(`unterminated string: ${line}`);
      src = unescape(m[1]);
      rest = m[2];
    } else {
      throw new Error(`unexpected source literal: ${line}`);
    }

    const tail = /^, (true|false), "([^"]*)", "([^"]*)", "([^"]*)"$/.exec(rest);
    if (!tail) throw new Error(`unexpected rule tail: ${line}`);
    const [, ci, name, severity, findingType] = tail;
    const indent = line.slice(0, line.length - line.trimStart().length);
    return `${indent}(&${enc(src)}, ${ci}, &${enc(name)}, "${severity}", &${enc(findingType)}),`;
  });

  const header =
    DEFS_ENC +
    '\n        // XOR-encoded (PATTERN_XOR_KEY) — decoded once at init so none of this\n' +
    '        // signature vocabulary sits in the shipped EXE as plaintext (VT).';
  const out = text.slice(0, i) + header + lines.join('\n') + text.slice(end);
  const count = (out.match(/\(&\[/g) || []).length;
  return [out, `MALWARE_RULES: ${count} rules`];
}

// ===== run =====
edit('scanner.rs', (t) => {
  const [t2, msg] = encodeMalwareRules(t);
  summary.push(`scanner.rs: ${msg}`);
  return t2;
});

edit('config_scanner.rs', (t) => {
  let s = t;
  for (const name of ['ARTIFACT_DIR_EXACT', 'CHEAT_MODULE_KEYS', 'STRONG_KEYS']) {
    const [next, msg] = encodeStringList(s, name);
    s = next;
    summary.push(`config_scanner.rs: ${msg}`);
  }
  {
    const [next, msg] = encodeConstRegex(s, 'ARTIFACT_EXE_RE');
    s = next;
    summary.push(`config_scanner.rs: ${msg}`);
  }
  for (const name of ['KW_RE', 'SIGNAL_RE']) {
    const [next, msg] = encodeStaticRegex(s, name);
    s = next;
    summary.push(`config_scanner.rs: ${msg}`);
  }
  return s;
});

edit('obfuscation.rs', (t) => {
  const [t2, msg] = encodeStringList(t, 'ZELIX_MARKERS');
  summary.push(`obfuscation.rs: ${msg}`);
  return t2;
});

console.log(summary.join('\n'));
