/**
 * WonderAnalyzer - %APPDATA% Cheat Config Scanner (launcher-scoped)
 *
 * Instead of reading every file in AppData, this scanner:
 *   1. DISCOVERS Minecraft launcher folders inside %APPDATA%
 *      (.minecraft, PrismLauncher, MultiMC, PolyMC, ATLauncher, CurseForge,
 *       Feather, Badlion, LabyMod, Modrinth, HMCL, GDLauncher, TLauncher...)
 *      either by folder name, by launcher marker files (launcher_profiles.json,
 *      prismlauncher.cfg, minecraftinstances.json, ...) or by a classic
 *      Minecraft game-dir layout (versions/ + libraries/).
 *   2. Only reads CONFIG-FORMAT files inside those launcher folders
 *      (.config, .conf, .cfg, .ini, .txt, .json, .yaml, .yml, .toml,
 *       .properties) - no other apps, no other formats.
 *   3. Reports a file only when its CONTENT is a cheat configuration:
 *      config-shaped structure AND at least one cheat signature match.
 */

const fs = require('fs');
const path = require('path');
const { CHEAT_PATTERNS, SUSPICIOUS_FILE_NAMES } = require('./patterns');

const MAX_FILE_SIZE = 2 * 1024 * 1024;   // skip files larger than 2 MB
const MAX_LOG_FILE_SIZE = 32 * 1024 * 1024; // logs may be huge (tail-read up to 1 MB)
const MAX_ANALYZE_SIZE = 1024 * 1024;    // analyze at most the first 1 MB
const MAX_CANDIDATES = 30000;            // safety cap on files considered
const MAX_MATCHES_PER_FILE = 60;         // stop collecting matches after this

// ONLY these config formats are read - everything else is ignored
const TEXT_EXTENSIONS = new Set([
  '.config', '.conf', '.cfg', '.ini', '.txt', '.json', '.yaml', '.yml', '.toml', '.properties', '.log',
]);

// Known Minecraft launcher / game folder names in %APPDATA% (lowercased)
const LAUNCHER_DIR_NAMES = new Set([
  '.minecraft', 'minecraft',
  'prismlauncher', 'prism launcher',
  'multimc',
  'polymc',
  'hmcl', '.hmcl',
  'atlauncher',
  'gdlauncher_next', 'gdlauncher',
  'curseforge',
  'feather', '.feather', 'featherclient',
  'badlion', 'badlionclient',
  'labymod', '.labymod',
  'modrinth', '.modrinth',
  'tlauncher', '.tlauncher',
  'skyclient', '.skyclient',
  'shiginima',
  'lunarclient', '.lunarclient', 'lunar client',
  'feather launcher', 'badlion client',
]);

// Files that identify a folder as launcher-managed, regardless of its name
const LAUNCHER_MARKER_FILES = [
  'launcher_profiles.json',   // official launcher & many forks
  'minecraftinstances.json',  // CurseForge / legacy Twitch
  'prismlauncher.cfg',        // Prism Launcher
  'multimc.cfg',              // MultiMC
  'polymc.cfg',               // PolyMC
  'atlauncher.cfg',           // ATLauncher
  'accounts.json',            // some third-party launchers
];

// Directories never worth walking inside launcher folders
// NOTE: 'logs' is intentionally NOT skipped — .minecraft/logs/latest.log is a
// scan target (cheat-module evidence in game logs).
const SKIP_DIRS = new Set([
  'node_modules', '.git', '$recycle.bin', 'system volume information',
  'cache', 'caches', 'code cache', 'gpucache', 'shadercache',
  'blob_storage', 'service worker', 'crashpad', 'crashdumps',
  // Electron/browser profile junk (Feather, Badlion, LabyMod launchers):
  'local storage', 'session storage', 'network', 'sentry', 'partitions',
  'dawngraphitecache', 'dawnwebgpucache', 'dawncache', 'indexeddb',
  'databases', 'file system',
]);

// ===== Cheat-tool artifacts (zenith-macros, .vapeclient, ...) =====
const ARTIFACT_DIR_EXACT = new Set([
  'zenith-macros', '.zenith-macros', 'zenith', '.zenith',
  '.vapeclient', 'vapeclient', '.vape', 'vape', 'wurst', '.wurst',
]);
const ARTIFACT_EXE_RE = /(zenith[-_\s]?macros?|\bvape\b|\bwurst\b|aristois|aimware|astolfo|novoline|pandaware|liquid[-_\s]?bounce|rise[-_\s]?client|dort[-_\s]?ware|bleachhack|sal[-_\s]?hack|horion|phobos)/i;

function is_artifact_dir_name(name) {
  const l = name.toLowerCase();
  return ARTIFACT_DIR_EXACT.has(l) || l.startsWith('.vape') ||
    l.startsWith('zenith') || l.startsWith('.zenith') ||
    l.startsWith('wurst') || l.startsWith('.wurst');
}

// ===== Verified first-party clients: mentions, never threats =====
function verified_client_label(name) {
  switch (name.toLowerCase()) {
    case '.feather': case 'feather': case 'featherclient': case 'feather launcher': return 'Feather Client';
    case 'lunarclient': case '.lunarclient': case 'lunar client': return 'Lunar Client';
    case 'badlion': case 'badlionclient': case 'badlion client': return 'Badlion Client';
    case 'labymod': case '.labymod': return 'LabyMod';
    default: return null;
  }
}

// ===== Diagnostic files: mentions only, never threats (rasadhlp FP fix) =====
function is_diagnostic_file(lowerName) {
  return (lowerName.startsWith('crash-') && lowerName.endsWith('.txt')) ||
    lowerName.startsWith('hs_err_') || lowerName.endsWith('.dmp');
}

// Report/forensics tool output folders — never read.
function is_report_artifact_dir(lowerName) {
  return lowerName.includes('precisionscan') ||
    lowerName.includes('mod-forensics') ||
    lowerName.includes('forensics-report');
}

// Java/source patterns that are pure noise in .txt/.json config files.
const CONFIG_EXCLUDE_NAMES = new Set([
  'CheatConfig', 'ModuleSystem', 'ModuleCategory', 'Settings', 'ProxyConnection',
]);

// Bare cheat-module keys (`"scaffold": {`, `fly = true`) — regexes need word
// pairs like "scaffold hack", configs write bare keys. All score medium/weak.
const BARE_KEY_RE = /^\s*["']?([A-Za-z][A-Za-z0-9_. -]{0,40})["']?\s*[=:]\s*(.*)$/gm;
const CHEAT_MODULE_KEYS = new Set([
  'killaura', 'kill aura', 'aimbot', 'aim assist', 'triggerbot', 'scaffold', 'autocrystal',
  'bedaura', 'cheststeal', 'packetfly', 'disabler', 'velocity', 'esp', 'fly', 'freecam',
  'freelook', 'reach', 'xray', 'tracers', 'fullbright', 'bhop', 'noslow', 'autofish',
  'autototem', 'autoclicker', 'scaffoldwalk', 'jesuswalk', 'waterwalk', 'noclip', 'phase',
  'nuker', 'wallhack', 'blink', 'longjump', 'highjump', 'noslowdown', 'spiderclimb',
]);
const STRONG_KEYS = new Set([
  'killaura', 'aimbot', 'triggerbot', 'scaffold', 'autocrystal',
  'bedaura', 'cheststeal', 'packetfly', 'disabler', 'autoclicker',
]);

function bareKeyMatches(content, alreadyMatched) {
  const out = [];
  const seen = new Set();
  BARE_KEY_RE.lastIndex = 0;
  let m;
  while ((m = BARE_KEY_RE.exec(content)) !== null) {
    const keyRaw = (m[1] || '').trim();
    const value = (m[2] || '').trim();
    const keyNorm = keyRaw.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!CHEAT_MODULE_KEYS.has(keyNorm)) continue;
    const v = value.replace(/^["']|["']$/g, '').toLowerCase();
    const falsy = v === '' || v === 'false' || v === '0' || v === 'off' || v === 'null' || v === '[]';
    if (falsy && !STRONG_KEYS.has(keyNorm)) continue;
    if (seen.has(keyNorm)) continue;
    seen.add(keyNorm);
    // Skip when a real pattern already matched the same key (no double-count)
    const dup = alreadyMatched.some(x =>
      x.patternName.toLowerCase().replace(/[^a-z0-9]/g, '') === keyNorm);
    if (dup) continue;
    out.push({
      patternName: `Module:${keyRaw}`,
      category: '🧩 Cheat Module Keys',
      severity: 'medium',
      context: m[0].trim().substring(0, 160),
      type: 'struct_bare_key',
    });
  }
  return out;
}

// Known performance optimizers: never flagged — only *mentioned* (info level)
// so the user can see which optimizer they are using.
const OPTIMIZER_EXPLAINED_PATTERNS = ['CrystalOptimizer'];

function detectOptimizer(fileName, content) {
  const has = (s, nd) => s.toLowerCase().includes(nd);
  if (has(fileName, 'marlow') || has(content, 'marlow')) return "Marlow's Crystal Optimizer";
  return null;
}

function isLogName(fileName) {
  const l = fileName.toLowerCase();
  return l.endsWith('.log') || l === 'log.txt' || l === 'logs.txt';
}

// Extensions that are configuration files by definition (still need cheat content)
const CONFIG_EXTENSIONS = new Set([
  '.config', '.cfg', '.conf', '.ini', '.toml', '.properties',
  '.json', '.yml', '.yaml', '.txt', '.properties',
]);

// Words that indicate configuration-style semantics inside plain text files
const CONFIG_KEYWORDS = /\b(enabled|disabled|keybind|key\s*bind|bind|module|modules|settings?|toggle[sd]?|categor(y|ies)|mode|active|visible|autoclicker|killaura|reach|cps|scaffold|velocity)\b/i;

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const SEVERITY_WEIGHT = { critical: 40, high: 25, medium: 12, low: 5 };

class ConfigScanner {
  constructor(webContents) {
    this.webContents = webContents;
    this.aborted = false;
    this.findings = [];
    this.scanned = 0;
    this.criticalCount = 0;
    this.warningCount = 0;
    this.optimizerCount = 0;
    this.walkedDirs = 0;
  }

  abort() {
    this.aborted = true;
  }

  /**
   * Scan %APPDATA% for cheat configs, restricted to Minecraft launcher folders
   */
  async scan(rootPath) {
    this.aborted = false;
    this.findings = [];
    this.scanned = 0;
    this.criticalCount = 0;
    this.warningCount = 0;
    this.optimizerCount = 0;
    this.walkedDirs = 0;

    this.emit('config-scan-progress', {
      phase: `Discovering Minecraft launchers in ${rootPath}...`,
      current: 0, total: 0, percent: 0,
      currentMod: null, found: 0, criticalCount: 0, warningCount: 0
    });

    // Phase 1: find launcher folders + cheat-tool artifact folders
    const { launchers, artifacts, rootExes } = await this.discoverLaunchers(rootPath);
    const launcherNames = launchers
      .map(p => path.relative(rootPath, p) || p)
      .sort((a, b) => a.localeCompare(b));

    // Cheat-tool folders always report (even when empty) + root .exe rule
    for (const dir of artifacts) {
      if (this.aborted) break;
      const rel = path.relative(rootPath, dir) || dir;
      this.findings.push(this.buildArtifactFinding(rel, dir, 0, 'Cheat Tool Artifact',
        `"${path.basename(dir)}" is the data folder of a known cheat tool — detected by folder name`));
      this.criticalCount++;
    }
    for (const exe of rootExes) {
      if (this.aborted) break;
      const rel = path.relative(rootPath, exe) || exe;
      let size = 0; try { size = fs.statSync(exe).size; } catch (e) {}
      this.findings.push(this.buildArtifactFinding(rel, exe, size, 'Cheat Tool Executable',
        `"${path.basename(exe)}" matches a known cheat tool's executable name`));
      this.criticalCount++;
    }

    if (this.aborted) {
      return {
        results: [],
        summary: this.generateSummary(0, launcherNames),
        aborted: true
      };
    }

    this.emit('config-scan-progress', {
      phase: launchers.length > 0
        ? `Found ${launchers.length} launcher(s): ${launcherNames.slice(0, 3).join(', ')}${launcherNames.length > 3 ? '...' : ''}`
        : 'No Minecraft launchers detected in %APPDATA%',
      current: 0, total: 0, percent: 0,
      currentMod: null, found: 0, criticalCount: 0, warningCount: 0
    });

    // Phase 2: index config-format files inside those folders only
    const candidates = [];
    for (const dir of launchers) {
      if (this.aborted) break;
      await this.walk(dir, candidates, rootPath, false, false);
    }
    for (const dir of artifacts) {
      if (this.aborted) break;
      await this.walk(dir, candidates, rootPath, false, true);
    }

    const abortedEarly = this.aborted;
    const total = candidates.length;

    // Phase 3: analyze content of each candidate
    const step = Math.max(1, Math.ceil(total / 200));
    for (let i = 0; i < total; i++) {
      if (this.aborted) break;

      const cand = candidates[i];
      const filePath = cand.path;
      const relPath = path.relative(rootPath, filePath);

      const finding = await this.analyzeFile(filePath, relPath, cand.kind);
      if (finding) {
        this.findings.push(finding);
        if (finding.threatLevel === 'info') {
          if (finding.modId === 'optimizer') this.optimizerCount++;
        } else if (finding.threatLevel === 'critical') this.criticalCount++;
        else this.warningCount++;
      }

      const isLast = i === total - 1;
      if (i % step === 0 || finding || isLast) {
        this.emit('config-scan-progress', {
          phase: `Analyzing configs (${i + (isLast && !this.aborted ? 1 : 0)}/${total})...`,
          current: i + 1,
          total,
          percent: Math.round(((i + 1) / total) * 100),
          currentMod: relPath,
          found: this.findings.filter(f => f.threatLevel !== 'info').length,
          criticalCount: this.criticalCount,
          warningCount: this.warningCount
        });
      }

      if (i % 25 === 0) await this.yieldToEventLoop();
    }

    const summary = this.generateSummary(total, launcherNames);

    if (this.aborted || abortedEarly) {
      return { results: this.findings, summary, aborted: true };
    }

    this.emit('config-scan-complete', { results: this.findings, summary });
    return { results: this.findings, summary };
  }

  // ===== Launcher discovery =====

  /**
   * Find Minecraft launcher folders: top-level in %APPDATA%, plus one level
   * deep for nested layouts like Vendor/.minecraft
   */
  async discoverLaunchers(root) {
    const found = [];
    const artifacts = [];
    const rootExes = [];
    const seen = new Set();
    const add = (p, list = found) => {
      const key = p.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        list.push(p);
      }
    };

    // Root-level cheat executables (zenith-macros.exe, ...)
    try {
      const rootEntries = await fs.promises.readdir(root, { withFileTypes: true });
      for (const e of rootEntries) {
        if (this.aborted) break;
        const n = e.name;
        if (e.isFile() && n.toLowerCase().endsWith('.exe') && ARTIFACT_EXE_RE.test(n)) {
          rootExes.push(path.join(root, n));
        }
      }
    } catch (e) {}

    let top = [];
    try {
      top = await fs.promises.readdir(root, { withFileTypes: true });
    } catch (e) {
      return { launchers: found, artifacts, rootExes };
    }

    for (const entry of top) {
      if (this.aborted) return { launchers: found, artifacts, rootExes };
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;

      const dir = path.join(root, entry.name);

      if (is_artifact_dir_name(entry.name)) {
        add(dir, artifacts);
        continue;
      }
      if (await this.isLauncherDir(dir)) {
        add(dir);
        continue;
      }

      // Peek one level deeper for nested launcher folders
      let subs = [];
      try {
        subs = await fs.promises.readdir(dir, { withFileTypes: true });
      } catch (e) {
        continue;
      }
      for (const sub of subs) {
        if (this.aborted) return { launchers: found, artifacts, rootExes };
        if (!sub.isDirectory() || sub.isSymbolicLink()) continue;
        const subDir = path.join(dir, sub.name);
        if (is_artifact_dir_name(sub.name)) add(subDir, artifacts);
        else if (await this.isLauncherDir(subDir)) add(subDir);
      }
    }

    found.sort();
    artifacts.sort();
    rootExes.sort();
    return { launchers: found, artifacts, rootExes };
  }

  async isLauncherDir(dir) {
    // 1. Known folder name
    const name = path.basename(dir).toLowerCase();
    if (LAUNCHER_DIR_NAMES.has(name)) return true;

    // 2. Launcher marker files
    for (const marker of LAUNCHER_MARKER_FILES) {
      const st = await this.statSafe(path.join(dir, marker));
      if (st && st.isFile()) return true;
    }

    // 3. Classic Minecraft game-dir layout (versions/ + libraries/)
    const versions = await this.statSafe(path.join(dir, 'versions'));
    const libraries = await this.statSafe(path.join(dir, 'libraries'));
    if (versions && versions.isDirectory() && libraries && libraries.isDirectory()) {
      return true;
    }

    return false;
  }

  // ===== File collection =====

  /**
   * Recursively collect candidate config files under a launcher folder
   */
  async walk(dir, out, root, inMods = false, inArtifact = false) {
    if (this.aborted || out.length >= MAX_CANDIDATES) return;

    let entries;
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch (e) {
      return; // permission denied / race with deletion
    }

    for (const entry of entries) {
      if (this.aborted || out.length >= MAX_CANDIDATES) return;

      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        const dname = entry.name.toLowerCase();
        if (SKIP_DIRS.has(dname) || is_report_artifact_dir(dname)) continue;
        // Cheat-tool data folders are analyzed as artifacts (any file format)
        if (is_artifact_dir_name(dname)) {
          this.walkedDirs++;
          await this.walk(full, out, root, false, true);
          continue;
        }
        // mods/: text files here are report artifacts (scan.log, forensics
        // dumps, ...) and are NEVER read — jars belong to the mod scanner.
        if (dname === 'mods') {
          this.walkedDirs++;
          await this.walk(full, out, root, true, false);
          continue;
        }
        this.walkedDirs++;
        if (this.walkedDirs % 100 === 0) {
          this.emit('config-scan-progress', {
            phase: `Indexing launcher files — ${out.length} config file(s) found so far...`,
            current: 0, total: 0, percent: 0,
            currentMod: path.relative(root, full) || entry.name,
            found: 0, criticalCount: 0, warningCount: 0
          });
          await this.yieldToEventLoop();
        }
        await this.walk(full, out, root);
      } else if (entry.isFile()) {
        if (inMods) continue; // jars only in mods/ — and jars are the mod scanner's job
        if (!inArtifact && !this.isCandidate(entry.name)) continue;
        try {
          const st = await fs.promises.stat(full);
          const max = isLogName(entry.name) ? MAX_LOG_FILE_SIZE : MAX_FILE_SIZE;
          if (!st.isFile() || st.size === 0 || st.size > max) continue;
        } catch (e) {
          continue;
        }
        out.push({ path: full, kind: inArtifact ? 'artifact' : 'text' });
      }
      // symlinks and other special entries are skipped
    }
  }

  /** Only config-format files are ever read */
  isCandidate(fileName) {
    const ext = path.extname(fileName).toLowerCase();
    return TEXT_EXTENSIONS.has(ext);
  }

  // ===== Content analysis =====

  /**
   * Read a file and return an analysis-shaped finding when its content is a
   * cheat configuration, otherwise null.
   */
  async analyzeFile(filePath, relPath, kind = 'text') {
    const fileName = path.basename(filePath);
    const lowerName = fileName.toLowerCase();
    const isLog = isLogName(lowerName);
    const isDiag = is_diagnostic_file(lowerName);
    const isArtifact = kind === 'artifact';

    // Verified first-party client files: mention only, never a threat
    const segs = relPath.replace(/\\/g, '/').toLowerCase().split('/');
    let trusted = null;
    for (const s of segs) {
      const l = verified_client_label(s);
      if (l) { trusted = l; break; }
    }

    let buf;
    try {
      buf = isLog
        ? await this.readLogTail(filePath)
        : await fs.promises.readFile(filePath);
    } catch (e) {
      return null;
    }

    this.scanned++;

    // Binary sniff
    if (buf.includes(0)) return null;

    const content = buf.toString('utf-8').slice(0, MAX_ANALYZE_SIZE);
    if (!content.trim()) return null;

    const ext = path.extname(filePath).toLowerCase();
    const optimizer = detectOptimizer(fileName, content);

    // Gate 1 (configs only): content must be structured like a configuration.
    // Logs, diagnostics, artifacts and trusted-client files skip this gate.
    let structure = { isConfig: true, strength: 0 };
    if (!isLog && !isDiag && !isArtifact && !trusted) {
      structure = this.analyzeStructure(content, ext);
      if (!structure.isConfig) {
        return optimizer ? this.buildOptimizerFinding(relPath, filePath, buf.length, ext, optimizer) : null;
      }
    } else {
      structure = this.analyzeStructure(content, ext);
    }

    // Gate 2: cheat signatures (optimizer-explained matches removed)
    let matches = this.matchPatterns(content);
    // Bare module keys (a log/diagnostic line is not a config key)
    if (!isLog && !isDiag) {
      matches = matches.concat(bareKeyMatches(content, matches));
    }
    if (optimizer) {
      matches = matches.filter(m => !OPTIMIZER_EXPLAINED_PATTERNS.includes(m.patternName));
    }
    // Logs only keep high-signal severities so chat mentioning casual names
    // can never flag a log file.
    if (isLog) {
      matches = matches.filter(m => m.severity === 'critical' || m.severity === 'high');
    }
    if (matches.length === 0) {
      return optimizer ? this.buildOptimizerFinding(relPath, filePath, buf.length, ext, optimizer) : null;
    }

    const rank = (s) => ({ critical: 4, high: 3, medium: 2, low: 1 }[s] || 1);

    // ===== Context-forced outcomes: mentions, never threats =====
    if (trusted) {
      return this.buildInfoFinding(relPath, filePath, buf.length, 'client',
        `${trusted} (official files)`,
        `${trusted} ships these files itself — matches are shown as an official-client mention and can never flag as a cheat.`,
        matches);
    }
    if (isDiag) {
      return this.buildInfoFinding(relPath, filePath, buf.length, 'report',
        `Diagnostic Report (${ext || 'txt'})`,
        `${matches.length} signature(s) matched inside a crash/diagnostic file — reported as mention only. Crash reports are never flagged as cheat configs.`,
        matches);
    }

    // ===== Weak/strong gate: a single QoL name never flags a file =====
    const strong = matches.some(m => rank(m.severity) >= 3);
    const weakCount = matches.filter(m => rank(m.severity) < 3).length;
    const relLower = relPath.replace(/\\/g, '/').toLowerCase();
    const signal = SUSPICIOUS_FILE_NAMES.some(r => r.test(fileName)) ||
      /wurst|vape|zenith|rise|cheat|hacked|hack|exploit|impact/.test(relLower);
    const pass = isArtifact
      ? matches.length >= 1
      : strong || weakCount >= 2 || (weakCount >= 1 && signal);
    if (!pass) {
      return optimizer ? this.buildOptimizerFinding(relPath, filePath, buf.length, ext, optimizer) : null;
    }

    const finding = this.buildFinding(relPath, filePath, buf.length, matches, structure, ext, isLog);
    if (isArtifact) {
      finding.modId = 'artifact';
      finding.modLoader = `Cheat Tool Artifact (${ext || 'no ext'})`;
    }
    return finding;
  }

  /** Logs can be tens of MB — only the most recent 1 MB matters. */
  async readLogTail(filePath) {
    const st = await fs.promises.stat(filePath);
    if (st.size <= MAX_ANALYZE_SIZE) return fs.promises.readFile(filePath);
    const fh = await fs.promises.open(filePath, 'r');
    try {
      const buf = Buffer.alloc(MAX_ANALYZE_SIZE);
      const { bytesRead } = await fh.read(buf, 0, MAX_ANALYZE_SIZE, st.size - MAX_ANALYZE_SIZE);
      return buf.slice(0, bytesRead);
    } finally {
      await fh.close();
    }
  }

  /**
   * Does the content look like a configuration file?
   */
  analyzeStructure(content, ext) {
    const trimmed = content.trimStart();
    const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[');

    let jsonValid = false;
    if (looksJson) {
      try {
        JSON.parse(content);
        jsonValid = true;
      } catch (e) {
        // truncated or concatenated JSON - fall through to heuristics
      }
    }

    // key = value / key: value pairs (at most 5 needed)
    const kvMatches = content.match(/^\s*["'#A-Za-z0-9_\-. ]{1,80}["']?\s*[=:]\s*\S.{0,200}/gm);
    const kvCount = kvMatches ? Math.min(kvMatches.length, 5) : 0;

    const hasIniSection = /^\s*\[[^\]\n]{1,100}\]\s*$/m.test(content);

    const typedConfig = CONFIG_EXTENSIONS.has(ext);
    const keywordHit = CONFIG_KEYWORDS.test(content);

    let isConfig = false;
    let strength = 0; // how config-like it is (used for scoring)

    if (typedConfig && (kvCount > 0 || jsonValid || hasIniSection)) {
      isConfig = true;
      strength = 2;
    } else if (jsonValid) {
      isConfig = true;
      strength = 2;
    } else if (looksJson && kvCount > 0) {
      isConfig = true; // truncated JSON with key/value pairs
      strength = 1;
    } else if (kvCount >= 2) {
      isConfig = true;
      strength = 1;
    } else if (kvCount >= 1 && keywordHit) {
      isConfig = true;
      strength = 1;
    } else if (hasIniSection && kvCount >= 1) {
      isConfig = true;
      strength = 1;
    }

    return { isConfig, strength, kvCount, jsonValid, typedConfig };
  }

  /**
   * Run the cheat pattern database against file content (line-aware)
   */
  matchPatterns(content) {
    const matches = [];
    const lines = content.split(/\r?\n/).slice(0, 30000);

    outer:
    for (const [categoryKey, category] of Object.entries(CHEAT_PATTERNS)) {
      if (categoryKey === 'mixins') continue;
      for (const pattern of category.patterns) {
        if (CONFIG_EXCLUDE_NAMES.has(pattern.name)) continue;
        if (matches.length >= MAX_MATCHES_PER_FILE) break outer;

        // Fullwidth patterns operate on the whole buffer
        if (category.label.includes('Fullwidth')) {
          if (pattern.regex.test(content)) {
            matches.push({
              patternName: pattern.name,
              category: category.label,
              severity: pattern.severity,
              context: null,
              type: 'string_match'
            });
          }
          continue;
        }

        for (const line of lines) {
          if (pattern.regex.test(line)) {
            matches.push({
              patternName: pattern.name,
              category: category.label,
              severity: pattern.severity,
              context: line.trim().substring(0, 200),
              type: 'string_match'
            });
            break;
          }
        }
      }
    }

    // Dedupe
    const seen = new Set();
    return matches.filter(m => {
      const key = `${m.patternName}:${m.category}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Assemble an analysis-shaped finding so the existing UI can render it
   */
  buildFinding(relPath, filePath, size, matches, structure, ext, isLog) {
    // Score
    let score = 0;
    let maxSeverity = 'low';
    for (const m of matches) {
      score += SEVERITY_WEIGHT[m.severity] || 5;
      if (SEVERITY_RANK[m.severity] > SEVERITY_RANK[maxSeverity]) {
        maxSeverity = m.severity;
      }
    }
    if (structure.strength >= 2) score += 10;              // typed config / valid JSON
    const fileName = path.basename(filePath);
    if (SUSPICIOUS_FILE_NAMES.some(r => r.test(fileName))) score += 10;
    score = Math.min(100, Math.round(score));

    // Threat level: strongest signature dominates, score can upgrade
    let threatLevel;
    if (maxSeverity === 'critical' || score >= 70) threatLevel = 'critical';
    else if (maxSeverity === 'high' || score >= 45) threatLevel = 'suspicious';
    else threatLevel = 'warning'; // any confirmed cheat signature in a config

    // Group findings into categories (same shape as the mod scanner)
    const categories = {};
    for (const m of matches) {
      if (!categories[m.category]) categories[m.category] = [];
      categories[m.category].push({
        name: m.patternName,
        severity: m.severity,
        file: null,
        context: m.context,
        type: m.type
      });
    }

    return {
      name: relPath,
      path: filePath,
      size,
      sizeFormatted: this.formatSize(size),
      hash: null,
      verified: false,
      verificationSource: null,
      modLoader: `${isLog ? 'Cheat Log' : 'Cheat Config'} (${ext || 'no ext'})`,
      modId: null,
      modVersion: null,
      modAuthor: null,
      threatLevel,
      threatScore: score,
      categories,
      stringMatches: matches,
      fileMatches: [],
      malwareFindings: [],
      structuralFindings: [{
        type: 'config_file',
        severity: 'info',
        message: isLog
          ? `Cheat module evidence in game log — ${matches.length} signature match(es) inside the file`
          : `Content is a cheat configuration — ${matches.length} signature match(es) inside the file`,
        details: null
      }],
      obfuscationAnalysis: null,
      fullwidthStrings: [],
      nestedJars: [],
      totalClasses: 0,
      totalFiles: 0,
      suspiciousFileCount: matches.length,
      manifest: null,
      downloadOrigin: null,
      isConfigScan: true,
    };
  }

  /** Non-threat mention: which optimizer the user is running. */
  buildOptimizerFinding(relPath, filePath, size, ext, optimizer) {
    return {
      name: relPath,
      path: filePath,
      size,
      sizeFormatted: this.formatSize(size),
      hash: null,
      verified: false,
      verificationSource: null,
      modLoader: optimizer, // the result card shows this — the mention itself
      modId: 'optimizer',
      modVersion: null,
      modAuthor: null,
      threatLevel: 'info',
      threatScore: 0,
      categories: {},
      stringMatches: [],
      fileMatches: [],
      malwareFindings: [],
      structuralFindings: [{
        type: 'optimizer',
        severity: 'info',
        message: `${optimizer} detected — a performance optimizer, not a cheat. Reported only so you know which optimizer is in use.`,
        details: null
      }],
      obfuscationAnalysis: null,
      fullwidthStrings: [],
      nestedJars: [],
      totalClasses: 0,
      totalFiles: 0,
      suspiciousFileCount: 0,
      manifest: null,
      downloadOrigin: null,
      isConfigScan: true,
    };
  }

  generateSummary(indexed, launchers) {
    return {
      launchers: launchers || [],
      indexed,
      analyzed: this.scanned,
      // Optimizer/official/report mentions are not "found" cheat configs
      found: this.findings.filter(f => f.threatLevel !== 'info').length,
      critical: this.findings.filter(f => f.threatLevel === 'critical').length,
      warning: this.findings.filter(f => f.threatLevel === 'warning' || f.threatLevel === 'suspicious').length,
      optimizers: this.findings.filter(f => f.threatLevel === 'info' && f.modId === 'optimizer').length,
      artifacts: this.findings.filter(f => f.modId === 'artifact').length,
      clients: this.findings.filter(f => f.threatLevel === 'info' && f.modId === 'client').length,
      timestamp: new Date().toISOString()
    };
  }

  /** Non-threat mention: official client / diagnostic report. */
  buildInfoFinding(relPath, filePath, size, modId, label, message, matches) {
    return {
      name: relPath,
      path: filePath,
      size,
      sizeFormatted: this.formatSize(size),
      hash: null,
      verified: false,
      verificationSource: null,
      modLoader: label,
      modId,
      modVersion: null,
      modAuthor: null,
      threatLevel: 'info',
      threatScore: 0,
      categories: {},
      stringMatches: matches.map(m => ({
        patternName: m.patternName, category: m.category,
        severity: m.severity, context: m.context, type: m.type
      })),
      fileMatches: [],
      malwareFindings: [],
      structuralFindings: [{ type: modId, severity: 'info', message, details: null }],
      obfuscationAnalysis: null,
      fullwidthStrings: [],
      nestedJars: [],
      totalClasses: 0,
      totalFiles: 0,
      suspiciousFileCount: 0,
      manifest: null,
      downloadOrigin: null,
      isConfigScan: true,
    };
  }

  /** Cheat-tool folder / executable discovered by name. */
  buildArtifactFinding(rel, absPath, size, label, message) {
    const safeRel = rel.replace(/\\/g, '/');
    return {
      name: safeRel,
      path: absPath,
      size,
      sizeFormatted: this.formatSize(size),
      hash: null,
      verified: false,
      verificationSource: null,
      modLoader: label,
      modId: 'artifact',
      modVersion: null,
      modAuthor: null,
      threatLevel: 'critical',
      threatScore: 60,
      categories: {
        '🎮 Cheat Tool Artifacts': [{
          name: label, severity: 'critical', file: null,
          context: message, type: 'string_match'
        }]
      },
      stringMatches: [{
        patternName: label, category: '🎮 Cheat Tool Artifacts',
        severity: 'critical', context: safeRel, type: 'string_match'
      }],
      fileMatches: [],
      malwareFindings: [],
      structuralFindings: [{ type: 'artifact', severity: 'critical', message, details: null }],
      obfuscationAnalysis: null,
      fullwidthStrings: [],
      nestedJars: [],
      totalClasses: 0,
      totalFiles: 0,
      suspiciousFileCount: 1,
      manifest: null,
      downloadOrigin: null,
      isConfigScan: true,
    };
  }

  formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  statSafe(p) {
    return fs.promises.stat(p).catch(() => null);
  }

  yieldToEventLoop() {
    return new Promise(resolve => setImmediate(resolve));
  }

  emit(channel, data) {
    if (this.webContents && !this.webContents.isDestroyed()) {
      this.webContents.send(channel, data);
    }
  }
}

module.exports = { ConfigScanner };
