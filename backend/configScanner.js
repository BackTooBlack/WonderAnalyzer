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
const MAX_ANALYZE_SIZE = 1024 * 1024;    // analyze at most the first 1 MB
const MAX_CANDIDATES = 30000;            // safety cap on files considered
const MAX_MATCHES_PER_FILE = 60;         // stop collecting matches after this

// ONLY these config formats are read - everything else is ignored
const TEXT_EXTENSIONS = new Set([
  '.config', '.conf', '.cfg', '.ini', '.txt', '.json', '.yaml', '.yml', '.toml', '.properties',
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
const SKIP_DIRS = new Set([
  'node_modules', '.git', '$recycle.bin', 'system volume information',
  'cache', 'caches', 'code cache', 'gpucache', 'shadercache',
  'blob_storage', 'service worker', 'crashpad', 'crashdumps', 'logs',
]);

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
    this.walkedDirs = 0;

    this.emit('config-scan-progress', {
      phase: `Discovering Minecraft launchers in ${rootPath}...`,
      current: 0, total: 0, percent: 0,
      currentMod: null, found: 0, criticalCount: 0, warningCount: 0
    });

    // Phase 1: find launcher folders
    const launchers = await this.discoverLaunchers(rootPath);
    const launcherNames = launchers
      .map(p => path.relative(rootPath, p) || p)
      .sort((a, b) => a.localeCompare(b));

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
      await this.walk(dir, candidates, rootPath);
    }

    const abortedEarly = this.aborted;
    const total = candidates.length;

    // Phase 3: analyze content of each candidate
    const step = Math.max(1, Math.ceil(total / 200));
    for (let i = 0; i < total; i++) {
      if (this.aborted) break;

      const filePath = candidates[i];
      const relPath = path.relative(rootPath, filePath);

      const finding = await this.analyzeFile(filePath, relPath);
      if (finding) {
        this.findings.push(finding);
        if (finding.threatLevel === 'critical') this.criticalCount++;
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
          found: this.findings.length,
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
    const seen = new Set();
    const add = (p) => {
      const key = p.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        found.push(p);
      }
    };

    let top = [];
    try {
      top = await fs.promises.readdir(root, { withFileTypes: true });
    } catch (e) {
      return found;
    }

    for (const entry of top) {
      if (this.aborted) return found;
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;

      const dir = path.join(root, entry.name);

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
        if (this.aborted) return found;
        if (!sub.isDirectory() || sub.isSymbolicLink()) continue;
        const subDir = path.join(dir, sub.name);
        if (await this.isLauncherDir(subDir)) add(subDir);
      }
    }

    return found;
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
  async walk(dir, out, root) {
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
        if (SKIP_DIRS.has(entry.name.toLowerCase())) continue;
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
        if (!this.isCandidate(entry.name)) continue;
        try {
          const st = await fs.promises.stat(full);
          if (!st.isFile() || st.size === 0 || st.size > MAX_FILE_SIZE) continue;
        } catch (e) {
          continue;
        }
        out.push(full);
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
  async analyzeFile(filePath, relPath) {
    let buf;
    try {
      buf = await fs.promises.readFile(filePath);
    } catch (e) {
      return null;
    }

    this.scanned++;

    // Binary sniff
    if (buf.includes(0)) return null;

    const content = buf.toString('utf-8').slice(0, MAX_ANALYZE_SIZE);
    if (!content.trim()) return null;

    const ext = path.extname(filePath).toLowerCase();

    // Gate 1: the content must be structured like a configuration
    const structure = this.analyzeStructure(content, ext);
    if (!structure.isConfig) return null;

    // Gate 2: it must contain cheat signatures
    const matches = this.matchPatterns(content);
    if (matches.length === 0) return null;

    return this.buildFinding(relPath, filePath, buf.length, matches, structure, ext);
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
    for (const category of Object.values(CHEAT_PATTERNS)) {
      for (const pattern of category.patterns) {
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
  buildFinding(relPath, filePath, size, matches, structure, ext) {
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
      modLoader: `Cheat Config (${ext || 'no ext'})`,
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
        message: `Content is a cheat configuration — ${matches.length} signature match(es) inside the file`,
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

  generateSummary(indexed, launchers) {
    return {
      launchers: launchers || [],
      indexed,
      analyzed: this.scanned,
      found: this.findings.length,
      critical: this.criticalCount,
      warning: this.warningCount,
      timestamp: new Date().toISOString()
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
