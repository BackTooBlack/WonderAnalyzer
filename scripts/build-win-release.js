#!/usr/bin/env node
// Builds the Windows 7 compatible release binaries.
//
// Why this exists:
//  - The tier-1 `*-pc-windows-msvc` std shipped with modern rustc imports
//    Win8+ APIs (GetSystemTimePreciseAsFileTime, WaitOnAddress via
//    api-ms-win-core-synch-l1-2-0.dll), so those exes die on Win7/8 with
//    0xC0000139 before main() runs.
//  - `*-win7-windows-msvc` targets are tier 3: no prebuilt std, so we build
//    std from source with `-Zbuild-std`. The target sets
//    target_vendor="win7", which also makes getrandom pick its Win7-safe
//    advapi32 RNG backend instead of bcryptprimitives.dll (Win10+), and
//    makes Rust std use Win7-era clock/sync APIs (GetProcAddress-guarded
//    fallbacks instead of static imports).
//  - `-Zbuild-std` is a nightly-only flag, but RUSTC_BOOTSTRAP=1 lets the
//    stable toolchain accept it. Stable cargo is required here: nightly
//    cargo 1.101's build-dep output layout pushed one proc-macro DLL to
//    exactly 260 chars (MAX_PATH) in this deep checkout, which MSVC
//    link.exe cannot create (LNK1104). Stable cargo 1.98 keeps those
//    paths in deps\ (shorter), so the wall is never hit.
//  - `+crt-static` links the UCRT/vcruntime statically, so no VC++ redist
//    or KB2999226 update is needed on Windows 7.
//  - src-tauri/vendor/{ctor,dtor} are patched (see Cargo.toml [patch])
//    because upstream ctor/dtor reject target_vendor="win7".
//
// Usage: node scripts/build-win-release.js [x64|x86]   (default: both)

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const repo = path.resolve(__dirname, '..');
const srcTauri = path.join(repo, 'src-tauri');
const distDir = path.resolve(repo, '..', 'dist');

const TARGETS = {
  x64: {
    triple: 'x86_64-win7-windows-msvc',
    artifact: 'WonderAnalyzer.exe',
  },
  x86: {
    triple: 'i686-win7-windows-msvc',
    artifact: 'WonderAnalyzer-x86.exe',
  },
};

const args = process.argv.slice(2);
const wanted = args.length
  ? args.map((a) => {
      if (!TARGETS[a]) {
        console.error(`unknown target "${a}" (expected x64 or x86)`);
        process.exit(2);
      }
      return a;
    })
  : ['x64', 'x86'];

function fail(msg) {
  console.error(`BUILD_WIN7_FAIL: ${msg}`);
  process.exit(1);
}

for (const key of wanted) {
  const t = TARGETS[key];
  console.log(`--- building ${t.triple} (release, +crt-static, -Zbuild-std)`);
  const res = spawnSync(
    'cargo',
    [
      'build',
      '--release',
      '--target', t.triple,
      '-Zbuild-std',
    ],
    {
      cwd: srcTauri,
      stdio: 'inherit',
      env: {
        ...process.env,
        RUSTC_BOOTSTRAP: '1', // allow -Zbuild-std on the stable toolchain
        RUSTFLAGS: '-C target-feature=+crt-static',
      },
    }
  );
  if (res.status !== 0) {
    fail(`cargo build failed for ${t.triple} (exit ${res.status})`);
  }

  const exe = path.join(srcTauri, 'target', t.triple, 'release', 'wonder-analyzer.exe');
  if (!fs.existsSync(exe)) fail(`expected output missing: ${exe}`);

  // Static Windows 7 gate: fail the build if the exe could not start
  // there (post-Win7 imports, dynamic CRT, wrong subsystem/OS version).
  const arch = key;
  const gate = spawnSync('node', [path.join(repo, 'tools', 'check-win7-compat.js'), exe, '--arch', arch], {
    stdio: 'inherit',
  });
  if (gate.status !== 0) fail(`check-win7-compat failed for ${t.triple}`);

  fs.mkdirSync(distDir, { recursive: true });
  const dest = path.join(distDir, t.artifact);
  fs.copyFileSync(exe, dest);
  // x64 also replaces the working copy at the repo root (what the test
  // battery and users run day-to-day).
  if (key === 'x64') {
    fs.copyFileSync(exe, path.join(repo, 'WonderAnalyzer.exe'));
  }
  console.log(`OK ${t.triple} -> ${dest}`);
}

console.log('BUILD_WIN7_PASS');
