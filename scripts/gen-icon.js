/**
 * Generates a 1024x1024 PNG icon for WonderAnalyzer (gradient shield),
 * hand-rolled PNG encoder (zlib + CRC32), output: assets-src/wonder-icon.png
 * Run: node scripts/gen-icon.js
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZE = 1024;
const SCALE = SIZE / 64; // shield drawn in a 64x64 design space

// CRC32
const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])));
  return Buffer.concat([len, typeBuf, data, crc]);
}

// Shield half-width at design-y (matches the app's SVG shield silhouette)
function halfWidth(y) {
  if (y < 4 || y > 62) return 0;
  if (y < 16) return 26 * ((y - 4) / 12);
  if (y <= 36) return 26;
  const t = (y - 36) / 26;
  return 26 * Math.sqrt(Math.max(0, 1 - t * t));
}

function insideShield(x, y) {
  return Math.abs(x - 32) <= halfWidth(y);
}

// Diagonal gradient #00f0ff -> #7c3aed
function lerp(a, b, t) { return Math.round(a + (b - a) * t); }
function gradient(x, y, alpha) {
  const t = Math.min(1, Math.max(0, (x + y) / 128));
  return [
    lerp(0x00, 0x7c, t),
    lerp(0xf0, 0x3a, t),
    lerp(0xff, 0xed, t),
    alpha,
  ];
}

const rows = [];
for (let py = 0; py < SIZE; py++) {
  const row = Buffer.alloc(1 + SIZE * 4);
  row[0] = 0; // filter: none
  const y = py / SCALE + 0.5 / SCALE;
  for (let px = 0; px < SIZE; px++) {
    const x = px / SCALE + 0.5 / SCALE;
    const o = 1 + px * 4;

    let [r, g, b, a] = [0, 0, 0, 0];
    if (insideShield(x, y)) {
      // outer shield body
      [r, g, b, a] = gradient(x, y, 235);
      // inner shield (scaled 0.62 about the visual centre) — brighter core
      const ix = (x - 32) / 0.62 + 32;
      const iy = (y - 34) / 0.62 + 34;
      if (insideShield(ix, iy)) {
        const [ir, ig, ib] = gradient(ix, iy, 255);
        r = lerp(r, ir, 0.85);
        g = lerp(g, ig, 0.85);
        b = lerp(b, ib, 0.85);
        a = 255;
      } else {
        // rim highlight near the outline edge
        const w = halfWidth(y);
        const edge = w - Math.abs(x - 32);
        if (edge < 1.4) { r = 255; g = 255; b = 255; a = 255; }
      }
    }
    row[o] = r; row[o + 1] = g; row[o + 2] = b; row[o + 3] = a;
  }
  rows.push(row);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8;  // bit depth
ihdr[9] = 6;  // RGBA
const idat = zlib.deflateSync(Buffer.concat(rows), { level: 9 });

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', idat),
  chunk('IEND', Buffer.alloc(0)),
]);

const out = path.join(__dirname, '..', 'assets-src', 'wonder-icon.png');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, png);
console.log(`Wrote ${out} (${png.length} bytes)`);
