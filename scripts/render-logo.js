/**
 * Renders assets-src/wonder-logo.svg to PNG sizes via @resvg/resvg-js.
 * One-time setup (not a project dependency): npm i --no-save @resvg/resvg-js
 * Run: node scripts/render-logo.js
 * Output: assets-src/wonder-logo.png (1024) + wonder-logo-{512,256,128,64,32}.png
 */
const fs = require("fs");
const path = require("path");

let Resvg;
try {
  ({ Resvg } = require("@resvg/resvg-js"));
} catch (e) {
  console.error("Missing renderer — run: npm i --no-save @resvg/resvg-js");
  process.exit(1);
}

const svg = fs.readFileSync(path.join(__dirname, "..", "assets-src", "wonder-logo.svg"));
const outDir = path.join(__dirname, "..", "assets-src");

for (const size of [1024, 512, 256, 128, 64, 32]) {
  const resvg = new Resvg(svg, { fitTo: { mode: "width", value: size } });
  const png = resvg.render().asPng();
  const name = size === 1024 ? "wonder-logo.png" : `wonder-logo-${size}.png`;
  fs.writeFileSync(path.join(outDir, name), png);
  console.log(`wrote ${name} (${png.length} bytes)`);
}
