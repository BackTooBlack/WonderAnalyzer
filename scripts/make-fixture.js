/**
 * Builds a synthetic %APPDATA% tree exercising every scanner rule:
 *   launchers (.minecraft, PrismLauncher, .feather), cheat configs, a clean
 *   QoL file, a crash report (rasadhlp/freecam FPs), cheat-tool artifact
 *   folders + root exe, mods/ with a Zelix-obfuscated jar, echoclient and a
 *   legit jar, report artifacts that must never be read, a non-launcher dir.
 *
 * Usage: node scripts/make-fixture.js <rootDir>
 */
const fs = require('fs');
const path = require('path');

const root = process.argv[2];
if (!root) {
  console.error('usage: node scripts/make-fixture.js <rootDir>');
  process.exit(2);
}
fs.rmSync(root, { recursive: true, force: true });
fs.mkdirSync(root, { recursive: true });

function w(rel, content) {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

// ===== minimal stored-zip (jar) writer =====
function crc32(data) {
  let crc = 0xffffffff;
  for (const b of data) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function makeJar(relPath, files) {
  const p = path.join(root, relPath);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const out = [];
  const central = [];
  let count = 0;
  const push = (buf) => out.push(Buffer.from(buf));
  for (const [name, dataRaw] of files) {
    const data = Buffer.isBuffer(dataRaw) ? dataRaw : Buffer.from(dataRaw);
    const nameB = Buffer.from(name, 'utf8');
    const crc = crc32(data);
    const offset = Buffer.concat(out).length;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(0, 8); // stored
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nameB.length, 26);
    lh.writeUInt16LE(0, 28);
    push(lh); push(nameB); push(data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nameB.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, nameB);
    count++;
  }
  const cdBuf = Buffer.concat(central);
  const cdOffset = Buffer.concat(out).length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(count, 8);
  eocd.writeUInt16LE(count, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  fs.writeFileSync(p, Buffer.concat([...out, cdBuf, eocd]));
}

// ===== .minecraft launcher =====
w('.minecraft/options.txt', 'lang:en_us\nrenderDistance:8\nfov:0.0\n');
w('.minecraft/launcher_profiles.json', '{\n  "profiles": {},\n  "version": 3\n}\n');
w('.minecraft/config/killaura.config', 'KillAura = true\ncps = 14\n');
w('.minecraft/config/modules.json', '{\n  "aimbot": {"enabled": true}\n}\n');
w('.minecraft/config/scaffold-helper.txt', 'scaffold = true\nbind = R\n');
w('.minecraft/config/qol-settings.json', '{\n  "autoSort": true\n}\n');
w('.minecraft/config/inventorysorter.cfg', 'autoSort = true\n');
w('.minecraft/config/marlows-crystal-optimizer.cfg',
  "Marlow's Crystal Optimizer = enabled\ncrystal optimizer mode = fast\n");
w('.minecraft/logs/latest.log',
  '[12:00:00] Joined\n[12:00:01] KillAura module activated\n');
w('.minecraft/crash-reports/crash-2026-09-23_10.00.00-client.txt',
  '---- Minecraft Crash Report ----\n'
  + 'freecam was active during the crash\n'
  + 'rasadhlp.dll: Remote Access AutoDial Helper (Microsoft Corporation)\n'
  + 'A "killaura" stack frame\n');

// mods/: jars are triaged; text files here must NEVER be read
w('.minecraft/mods/scan.log', 'killaura aimbot scaffold found\n');
w('.minecraft/mods/PrecisionScan-x/scan.log', 'killaura found\n');
w('.minecraft/mods/PrecisionScan-x/report.txt', 'killaura report\n');

makeJar('.minecraft/mods/cheat-zkm.jar', [
  ['fabric.mod.json', '{"id":"zkmcheat","version":"0.1.0"}'],
  ['zelix/a.class', Buffer.from([0xca, 0xfe, 0xba, 0xbe, 1, 0, 0, 0])],
  ['klassmaster/b.class', 'junk'],
  ['klassemaster/c.class', 'junk'],
  ['META-INF/zkm.dat', 'zkm'],
  ['klimax/d.class', 'junk'],
  ['zz/e.class', 'junk'],
]);
makeJar('.minecraft/mods/echoclient-1.0.jar', [
  ['fabric.mod.json', '{"id":"echoclient","version":"1.0"}'],
]);
makeJar('.minecraft/mods/legit-lib.jar', [
  ['fabric.mod.json', '{"id":"sodium","version":"0.6.0"}'],
  ['net/caffeinemc/sodium/Main.class', Buffer.from([0xca, 0xfe, 0xba, 0xbe])],
]);

// ===== PrismLauncher =====
w('PrismLauncher/prismlauncher.cfg', '[General]\ninstDir=instances\n');
w('PrismLauncher/instances/vanilla/autoSprint.txt', 'autoSprint = true\n');

// ===== Feather (verified client — mention only) =====
w('.feather/modules.json', '{\n  "killaura": true,\n  "esp": true\n}\n');

// ===== cheat-tool artifacts =====
w('zenith-macros/profiles.json', '{"profile": "zenith-macros"}\n');
w('.vapeclient/cache', 'vapeclient = v4\n');
w('zenith-macros.exe', 'MZ fake executable');

// ===== non-launcher folder: never read =====
w('NotALauncher/cheat.txt', 'killaura = true\n');

// ===== mod-scan fixture (used by --scan-mods / check-scan.js) =====
makeJar('modscan/goodmod.jar', [
  ['fabric.mod.json', '{"id":"goodmod","version":"1.0.0","authors":["Tester"]}'],
  ['com/example/GoodModClass.class', Buffer.from([0xca, 0xfe, 0xba, 0xbe])],
]);
makeJar('modscan/badmod.jar', [
  ['fabric.mod.json', '{"id":"badmod","version":"2.0.0","authors":["Tester"]}'],
  ['com/example/CheatModule.class', 'module manager'],
  ['assets/evil.txt',
    'Runtime.getRuntime().exec payload\n'
    + 'pastebin.com fetch\n'
    + 'discord.com/api/webhooks/123/token\n'],
]);
makeJar('modscan/unicode-mod.jar', [
  ['fabric.mod.json', '{"id":"unicodemod","version":"1.0.0"}'],
  ['assets/mod_fr.lang',
    'comment.test = préface password émoji 🚀 パスワード clipboard hijack suffix text padding here'],
]);

console.log('FIXTURE_OK: ' + root);
