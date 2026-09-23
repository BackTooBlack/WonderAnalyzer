// E2E checker for --scan-mods output JSON.
// Usage: node scripts/check-scan.js <path-to-scan.json>
// Asserts: clean mod is threatLevel=safe/score 0, cheaty mod is flagged, loader+modId parsed.
const fs = require("fs");
const file = process.argv[2];
let j;
try {
  j = JSON.parse(fs.readFileSync(file, "utf8"));
} catch (e) {
  console.error("FAIL: cannot parse " + file);
  process.exit(1);
}
const results = (j && j.results) || [];
if (!Array.isArray(results) || results.length < 2) {
  console.error("FAIL: expected >=2 results, got " + results.length);
  process.exit(1);
}
const good = results.find((r) => /^good/i.test(r.name || ""));
const bad = results.find((r) => /^bad/i.test(r.name || ""));
const errors = [];
if (!good) errors.push("good mod missing from results");
else {
  if (good.threatLevel !== "safe") errors.push("good mod threatLevel=" + good.threatLevel + " (want safe)");
  if (good.threatScore !== 0) errors.push("good mod threatScore=" + good.threatScore + " (want 0)");
}
if (!bad) errors.push("bad mod missing from results");
else {
  if (!(bad.threatScore > 0)) errors.push("bad mod threatScore=" + bad.threatScore + " (want >0)");
  if (bad.threatLevel === "safe") errors.push("bad mod threatLevel=safe (should be flagged)");
  if (!bad.modLoader) errors.push("bad mod modLoader missing");
  if (!bad.modId) errors.push("bad mod modId missing");
}
if (errors.length) {
  console.error("FAIL: " + errors.join("; "));
  process.exit(1);
}
console.log("E2E_MOD_SCAN_PASS (" + results.length + " mods, good=" + good.threatLevel + "/" + good.threatScore + ", bad=" + bad.threatLevel + "/" + bad.threatScore + ")");
