#!/usr/bin/env node
// Static Windows 7 compatibility gate for the shipped PE binaries.
//
// Fails if the exe could not even START on Windows 7 SP1:
//  - any load-time import of a DLL or function introduced after those OSes
//    (the classic symptom is 0xC0000139 STATUS_ENTRYPOINT_NOT_FOUND, which
//    kills the process before main() runs);
//  - a dynamic CRT (VCRUNTIME140 / api-ms-win-crt-* / MSVCP140) — Win7 only
//    has those via the VC++ redist / KB2999226 update, so release builds
//    must link the CRT statically;
//  - wrong subsystem / OS version fields or wrong machine type.
//
// Usage: node tools/check-win7-compat.js <exe> [--arch x64|x86]

'use strict';

const fs = require('fs');

// ---- deny lists (anything here = fail) ------------------------------------

const BAD_DLLS = [
  'bcryptprimitives.dll', // Win10+ (getrandom's modern RNG backend)
  'api-ms-win-core-synch-l1-2-0.dll', // Win8+ (WaitOnAddress)
  'api-ms-win-crt-',
  'vcruntime140.dll',
  'vcruntime140_1.dll',
  'msvcp140.dll',
  'ucrtbase.dll', // must be static, not imported
  'webview2loader.dll', // must be loaded dynamically, never at process start
  'shcore.dll', // Win8+ (SetProcessDpiAwareness etc.)
];

const BAD_FUNCS = [
  'GetSystemTimePreciseAsFileTime', // Win8+
  'GetSystemTimeAsFileTimeEx', // Win8+
  'WaitOnAddress', // Win8+
  'WakeByAddressAll', // Win8+
  'WakeByAddressSingle', // Win8+
  'SetThreadDescription', // Win10
  'GetThreadDescription', // Win10
  'PathCchCombineEx', // Win8
  'PathCchCanonicalizeEx', // Win8
  'ProcessPrng', // Win10 (only in bcryptprimitives.dll)
  'CreateFile2', // Win8
  'GetOverlappedResultEx', // Win8
  'PathCchCombine', // Win8
  'PathCchAppend', // Win8
  'PathCchRemoveFileSpec', // Win8
];

// DLLs we explicitly allow (Win7 SP1 present). Anything else fails closed.
const ALLOWED_DLLS = new Set([
  'advapi32.dll', 'bcrypt.dll', 'comctl32.dll', 'comdlg32.dll', 'crypt32.dll',
  'dwmapi.dll', 'gdi32.dll', 'gdiplus.dll', 'imm32.dll', 'iphlpapi.dll',
  'kernel32.dll', 'msvcrt.dll', 'netapi32.dll', 'ntdll.dll', 'ole32.dll',
  'oleaut32.dll', 'psapi.dll', 'rpcrt4.dll', 'secur32.dll', 'setupapi.dll',
  'shell32.dll', 'shlwapi.dll', 'user32.dll', 'userenv.dll', 'usp10.dll',
  'version.dll', 'winhttp.dll', 'wininet.dll', 'winmm.dll', 'wintrust.dll',
  'ws2_32.dll', 'wldap32.dll', 'wtsapi32.dll', 'winspool.drv', 'avicap32.dll',
  'dbghelp.dll', 'd3d9.dll', 'opengl32.dll', 'powrprof.dll', 'wldp.dll',
]);

// ---- tiny PE reader --------------------------------------------------------

function readPe(buf) {
  if (buf.length < 0x40 || buf.toString('latin1', 0, 2) !== 'MZ') {
    throw new Error('not an MZ executable');
  }
  const peOff = buf.readUInt32LE(0x3c);
  if (buf.toString('latin1', peOff, peOff + 4) !== 'PE\0\0') {
    throw new Error('PE signature missing');
  }
  const coff = peOff + 4;
  const machine = buf.readUInt16LE(coff);
  const nsec = buf.readUInt16LE(coff + 2);
  const optsz = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  if (magic !== 0x20b && magic !== 0x10b) {
    throw new Error(`expected PE32+ (0x20b) or PE32 (0x10b), got 0x${magic.toString(16)}`);
  }
  const is64 = magic === 0x20b;
  const subsystem = buf.readUInt16LE(opt + 68);
  const osMajor = buf.readUInt16LE(opt + 40);
  const osMinor = buf.readUInt16LE(opt + 42);
  const subsMajor = buf.readUInt16LE(opt + 48);
  const subsMinor = buf.readUInt16LE(opt + 50);
  const dd = opt + (is64 ? 112 : 96); // PE32+ vs PE32 data directories
  const importRva = buf.readUInt32LE(dd + 8);
  const thunkSize = is64 ? 8 : 4;

  const secs = [];
  for (let i = 0; i < nsec; i++) {
    const o = opt + optsz + i * 40;
    const va = buf.readUInt32LE(o + 12);
    const vsz = buf.readUInt32LE(o + 8);
    const rawsz = buf.readUInt32LE(o + 16);
    const raw = buf.readUInt32LE(o + 20);
    secs.push({ va, size: Math.max(vsz, rawsz), raw });
  }
  const r2o = (rva) => {
    for (const s of secs) {
      if (rva >= s.va && rva < s.va + s.size) return s.raw + (rva - s.va);
    }
    return null;
  };

  // import descriptors -> (dll, [functions])
  const imports = new Map();
  let o = importRva ? r2o(importRva) : null;
  if (o != null) {
    for (;;) {
      const iltRva = buf.readUInt32LE(o);
      const nameRva = buf.readUInt32LE(o + 12);
      if (nameRva === 0) break;
      const nameOff = r2o(nameRva);
      const end = buf.indexOf(0, nameOff);
      const dll = buf.toString('latin1', nameOff, end).toLowerCase();
      const funcs = [];
      let t = r2o(iltRva || buf.readUInt32LE(o + 16));
      if (t != null) {
        for (;;) {
          // PE32+ thunks are 8 bytes (low dword at t, high at t+4);
          // PE32 thunks are a single 4-byte dword.
          const ent = is64
            ? buf.readUInt32LE(t + 4) * 0x1_0000_0000 + buf.readUInt32LE(t)
            : buf.readUInt32LE(t);
          if (ent === 0) break;
          const ordinalFlag = is64 ? 0x8000_0000_0000_0000 : 0x8000_0000;
          if (ent >= ordinalFlag) {
            funcs.push(`#${ent & 0xffff}`); // ordinal-only import
          } else {
            const nOff = r2o(ent & 0x7fff_ffff);
            if (nOff != null) funcs.push(buf.toString('latin1', nOff + 2, buf.indexOf(0, nOff + 2)));
          }
          t += thunkSize;
        }
      }
      if (!imports.has(dll)) imports.set(dll, []);
      imports.get(dll).push(...funcs);
      o += 20;
    }
  }
  return { machine, is64, subsystem, osMajor, osMinor, subsMajor, subsMinor, imports };
}

// ---- gate ------------------------------------------------------------------

function main() {
  const exePath = process.argv[2];
  if (!exePath) {
    console.error('usage: node tools/check-win7-compat.js <exe> [--arch x64|x86]');
    process.exit(2);
  }
  const archIdx = process.argv.indexOf('--arch');
  const arch = archIdx > -1 ? process.argv[archIdx + 1] : null;

  const pe = readPe(fs.readFileSync(exePath));

  if (process.argv.includes('--dump')) {
    for (const [dll, funcs] of pe.imports) {
      for (const f of funcs) console.log(`${dll}!${f}`);
    }
    return;
  }
  const errors = [];

  const expectMachine = arch === 'x64' ? 0x8664 : arch === 'x86' ? 0x14c : null;
  if (expectMachine && pe.machine !== expectMachine) {
    errors.push(`machine 0x${pe.machine.toString(16)} != expected 0x${expectMachine.toString(16)} (${arch})`);
  }
  if (pe.subsystem !== 1 && pe.subsystem !== 2) {
    errors.push(`subsystem ${pe.subsystem} not in {1=NATIVE, 2=WINDOWS_GUI}`);
  }
  // Loader rejects exes whose OS/subsystem version exceeds the OS.
  // Win7 = 6.1 (target is Win7-only, so cap at 6.1).
  if (pe.osMajor > 6 || (pe.osMajor === 6 && pe.osMinor > 1)) {
    errors.push(`OS version ${pe.osMajor}.${pe.osMinor} > 6.1`);
  }
  if (pe.subsMajor > 6 || (pe.subsMajor === 6 && pe.subsMinor > 1)) {
    errors.push(`subsystem version ${pe.subsMajor}.${pe.subsMinor} > 6.1`);
  }

  for (const [dll, funcs] of pe.imports) {
    const badDll = BAD_DLLS.find((b) => dll === b || dll.startsWith(b));
    if (badDll) errors.push(`imports post-Win7 DLL ${dll} (matched "${badDll}")`);
    else if (!ALLOWED_DLLS.has(dll)) errors.push(`unrecognized DLL ${dll} — verify Win7 availability and add to allowlist`);

    for (const f of funcs) {
      if (BAD_FUNCS.includes(f)) errors.push(`imports post-Win7 function ${dll}!${f}`);
    }
  }

  const summary = [...pe.imports.entries()]
    .map(([dll, f]) => `${dll}(${f.length})`)
    .sort()
    .join(', ');
  const funcCount = [...pe.imports.values()].reduce((n, f) => n + f.length, 0);
  console.log(`file:      ${exePath}`);
  console.log(`machine:   0x${pe.machine.toString(16)}  pe: ${pe.is64 ? 'PE32+' : 'PE32'}  subsystem: ${pe.subsystem}  os: ${pe.osMajor}.${pe.osMinor}  subsys: ${pe.subsMajor}.${pe.subsMinor}`);
  console.log(`dlls (${pe.imports.size}, ${funcCount} named imports): ${summary}`);

  if (funcCount === 0) {
    errors.push('parsed 0 named imports — PE import walk is broken, gate would pass anything');
  }

  if (errors.length) {
    for (const e of errors) console.error(`WIN7_COMPAT_FAIL: ${e}`);
    process.exit(1);
  }
  console.log('WIN7_COMPAT_PASS');
}

main();
