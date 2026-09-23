/**
 * Core JAR Scanner Engine
 * Reads mods from disk, extracts contents, coordinates all analysis modules
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const yauzl = require('yauzl');
const { CHEAT_PATTERNS, SUSPICIOUS_FILE_NAMES } = require('./patterns');
const { verifyHash } = require('./verifier');
const { analyzeObfuscation } = require('./obfuscation');
const { scanForMalware } = require('./malware');
const { analyzeStructure } = require('./structure');

class ModScanner {
  constructor(webContents) {
    this.webContents = webContents;
    this.aborted = false;
    this.results = [];
  }

  abort() {
    this.aborted = true;
  }

  /**
   * Scan a directory for mod JAR files
   */
  async scanDirectory(dirPath) {
    this.aborted = false;
    this.results = [];

    if (!fs.existsSync(dirPath)) {
      throw new Error(`Directory not found: ${dirPath}`);
    }

    const files = fs.readdirSync(dirPath);
    const jarFiles = files.filter(f => f.endsWith('.jar'));

    if (jarFiles.length === 0) {
      throw new Error('No .jar files found in the selected directory');
    }

    this.emit('scan-progress', {
      total: jarFiles.length,
      current: 0,
      phase: 'Starting scan...',
      currentMod: null
    });

    for (let i = 0; i < jarFiles.length; i++) {
      if (this.aborted) break;

      const jarPath = path.join(dirPath, jarFiles[i]);
      const jarSize = fs.statSync(jarPath).size;

      this.emit('scan-progress', {
        total: jarFiles.length,
        current: i,
        phase: `Scanning ${jarFiles[i]}...`,
        currentMod: jarFiles[i],
        percent: Math.round((i / jarFiles.length) * 100)
      });

      try {
        const analysis = await this.analyzeMod(jarPath, jarFiles[i], jarSize);
        this.results.push(analysis);

        this.emit('mod-scanned', {
          name: jarFiles[i],
          analysis: analysis
        });
      } catch (err) {
        const errorResult = {
          name: jarFiles[i],
          path: jarPath,
          size: jarSize,
          error: err.message,
          threatLevel: 'error',
          threats: [],
          score: 0,
          hash: null,
          verified: false,
          files: []
        };
        this.results.push(errorResult);
        this.emit('mod-scanned', {
          name: jarFiles[i],
          analysis: errorResult
        });
      }
    }

    const summary = this.generateSummary();
    this.emit('scan-complete', { results: this.results, summary });

    return { results: this.results, summary };
  }

  /**
   * Analyze a single mod JAR file in depth
   */
  async analyzeMod(jarPath, fileName, fileSize) {
    const analysis = {
      name: fileName,
      path: jarPath,
      size: fileSize,
      sizeFormatted: this.formatSize(fileSize),
      hash: null,
      verified: false,
      verificationSource: null,
      modLoader: 'Unknown',
      modVersion: null,
      modAuthor: null,
      modId: null,
      threatLevel: 'safe',
      threatScore: 0,
      files: [],
      categories: {},
      stringMatches: [],
      fileMatches: [],
      structuralFindings: [],
      obfuscationAnalysis: null,
      malwareFindings: [],
      nestedJars: [],
      totalClasses: 0,
      totalFiles: 0,
      suspiciousFileCount: 0,
      fullwidthStrings: [],
      manifest: null,
      downloadOrigin: null,
    };

    // Step 1: Calculate hash
    analysis.hash = this.calculateHash(jarPath);

    // Step 2: Verify against Modrinth
    try {
      const verification = await verifyHash(analysis.hash);
      analysis.verified = verification.verified;
      analysis.verificationSource = verification.source;
    } catch (e) {
      // Hash verification failed, continue with analysis
    }

    // Step 3: Extract and analyze JAR contents
    const jarContents = await this.extractJarContents(jarPath);

    analysis.files = jarContents.entries;
    analysis.totalFiles = jarContents.entries.length;
    analysis.totalClasses = jarContents.entries.filter(e => e.name.endsWith('.class')).length;
    analysis.nestedJars = jarContents.nestedJars;

    // Step 4: Parse manifest
    if (jarContents.manifest) {
      analysis.manifest = this.parseManifest(jarContents.manifest);
      analysis.modVersion = analysis.manifest['Implementation-Version'] ||
                           analysis.manifest['Specification-Version'] || null;
      analysis.modAuthor = analysis.manifest['Created-By'] || null;
    }

    // Step 5: Pattern matching against all file paths and names
    analysis.fileMatches = this.matchFilePatterns(jarContents.entries);

    // Step 6: String analysis on extracted content
    analysis.stringMatches = this.matchStringPatterns(jarContents.textContent);

    // Step 7: Fullwidth Unicode detection
    analysis.fullwidthStrings = this.detectFullwidth(jarContents.textContent);

    // Step 8: Analyze nested JARs
    if (jarContents.nestedJars.length > 0) {
      analysis.structuralFindings.push({
        type: 'nested_jars',
        severity: 'warning',
        message: `Found ${jarContents.nestedJars.length} nested JAR(s) inside META-INF/jars/`,
        details: jarContents.nestedJars.map(j => j.name)
      });
    }

    // Step 9: Obfuscation analysis
    analysis.obfuscationAnalysis = analyzeObfuscation(jarContents.entries, jarContents.textContent);

    // Step 10: Malware scanning
    analysis.malwareFindings = scanForMalware(jarContents.textContent, jarContents.entries);

    // Step 11: Structural analysis
    const structural = analyzeStructure(jarContents.entries, jarContents.textContent, analysis);
    analysis.structuralFindings.push(...structural);
    analysis.modLoader = structural.find(s => s.type === 'mod_loader')?.value || 'Unknown';
    analysis.modId = structural.find(s => s.type === 'mod_id')?.value || null;

    // Step 12: Calculate threat score
    this.calculateThreatScore(analysis);

    // Step 13: Categorize all findings
    analysis.categories = this.categorizeFindings(analysis);

    // Count suspicious files
    analysis.suspiciousFileCount = analysis.fileMatches.length + analysis.stringMatches.length +
      analysis.malwareFindings.length;

    return analysis;
  }

  /**
   * Extract all contents from a JAR file
   */
  extractJarContents(jarPath) {
    return new Promise((resolve, reject) => {
      const entries = [];
      let manifestContent = null;
      const nestedJars = [];
      const textContent = [];

      yauzl.open(jarPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);

        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          entries.push({
            name: entry.fileName,
            compressedSize: entry.compressedSize,
            uncompressedSize: entry.uncompressedSize,
            isDirectory: entry.fileName.endsWith('/')
          });

          // Read text-based files and class files for string extraction
          const isTextFile = /\.(json|txt|cfg|properties|mcmeta|xml|yml|yaml|toml|lang|gradle)$/i.test(entry.fileName);
          const isManifest = entry.fileName.toUpperCase() === 'META-INF/MANIFEST.MF';
          const isMixinConfig = /mixin.*\.json$/i.test(entry.fileName);
          const isNestedJar = entry.fileName.match(/^META-INF\/jars\/.*\.jar$/i);

          if (isManifest || isTextFile || isMixinConfig || isNestedJar) {
            zipfile.openReadStream(entry, (err, readStream) => {
              if (err) {
                zipfile.readEntry();
                return;
              }
              const chunks = [];
              readStream.on('data', (chunk) => chunks.push(chunk));
              readStream.on('end', () => {
                const content = Buffer.concat(chunks).toString('utf-8', 0, Math.min(chunks.reduce((a, c) => a + c.length, 0), 50000));

                if (isManifest) {
                  manifestContent = content;
                }
                if (isNestedJar) {
                  nestedJars.push({
                    name: entry.fileName,
                    size: entry.uncompressedSize
                  });
                }
                textContent.push({
                  file: entry.fileName,
                  content: content
                });

                zipfile.readEntry();
              });
              readStream.on('error', () => zipfile.readEntry());
            });
          } else {
            zipfile.readEntry();
          }
        });

        zipfile.on('end', () => {
          resolve({ entries, manifestContent, nestedJars, textContent });
        });
        zipfile.on('error', (e) => reject(e));
      });
    });
  }

  /**
   * Match patterns against file paths and names
   */
  matchFilePatterns(entries) {
    const matches = [];

    for (const entry of entries) {
      if (entry.isDirectory) continue;

      for (const category of Object.values(CHEAT_PATTERNS)) {
        for (const pattern of category.patterns) {
          if (pattern.regex.test(entry.name)) {
            matches.push({
              file: entry.name,
              patternName: pattern.name,
              category: category.label,
              severity: pattern.severity,
              type: 'file_match'
            });
          }
        }
      }

      for (const regex of SUSPICIOUS_FILE_NAMES) {
        if (regex.test(entry.name)) {
          matches.push({
            file: entry.name,
            patternName: 'SuspiciousFileName',
            category: '📂 Suspicious Files',
            severity: 'medium',
            type: 'file_name'
          });
        }
      }
    }

    return matches;
  }

  /**
   * Match patterns against extracted text content
   */
  matchStringPatterns(textFiles) {
    const matches = [];

    for (const { file, content } of textFiles) {
      if (!content) continue;

      for (const category of Object.values(CHEAT_PATTERNS)) {
        for (const pattern of category.patterns) {
          // For fullwidth patterns, test directly
          if (category.label.includes('Fullwidth')) {
            if (pattern.regex.test(content)) {
              matches.push({
                file,
                patternName: pattern.name,
                category: category.label,
                severity: pattern.severity,
                type: 'string_match'
              });
            }
            continue;
          }

          // For string patterns, check with context
          const lines = content.split('\n');
          for (const line of lines) {
            if (pattern.regex.test(line)) {
              matches.push({
                file,
                patternName: pattern.name,
                category: category.label,
                severity: pattern.severity,
                type: 'string_match',
                context: line.trim().substring(0, 200)
              });
              break;
            }
          }
        }
      }
    }

    // Remove duplicates
    const seen = new Set();
    return matches.filter(m => {
      const key = `${m.file}:${m.patternName}:${m.category}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Detect fullwidth Unicode strings (used to hide cheat labels)
   */
  detectFullwidth(textFiles) {
    const fullwidthPatterns = [
      /[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}/g
    ];
    const results = [];

    for (const { file, content } of textFiles) {
      if (!content) continue;
      for (const regex of fullwidthPatterns) {
        const matches = content.match(regex);
        if (matches) {
          for (const match of matches) {
            results.push({
              file,
              raw: match,
              decoded: this.fullwidthToAscii(match)
            });
          }
        }
      }
    }

    return results;
  }

  /**
   * Convert fullwidth Unicode to ASCII
   */
  fullwidthToAscii(str) {
    return str.replace(/[\uFF01-\uFF5E]/g, (ch) =>
      String.fromCharCode(ch.charCodeAt(0) - 0xFEE0)
    ).replace(/\u3000/g, ' ');
  }

  /**
   * Calculate SHA-1 hash of a file
   */
  calculateHash(filePath) {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha1').update(content).digest('hex');
  }

  /**
   * Parse JAR manifest
   */
  parseManifest(content) {
    const props = {};
    const lines = content.split(/\r?\n/);
    let lastKey = null;

    for (const line of lines) {
      if (line.startsWith(' ') && lastKey) {
        props[lastKey] += line.trimStart();
      } else {
        const idx = line.indexOf(':');
        if (idx > 0) {
          lastKey = line.substring(0, idx).trim();
          props[lastKey] = line.substring(idx + 1).trim();
        }
      }
    }

    return props;
  }

  /**
   * Calculate threat score and level for a mod
   */
  calculateThreatScore(analysis) {
    if (analysis.verified) {
      analysis.threatScore = 0;
      analysis.threatLevel = 'safe';
      return;
    }

    let score = 0;

    // File pattern matches
    for (const match of analysis.fileMatches) {
      switch (match.severity) {
        case 'critical': score += 25; break;
        case 'high': score += 15; break;
        case 'medium': score += 8; break;
        case 'low': score += 3; break;
      }
    }

    // String matches
    for (const match of analysis.stringMatches) {
      switch (match.severity) {
        case 'critical': score += 20; break;
        case 'high': score += 12; break;
        case 'medium': score += 6; break;
        case 'low': score += 2; break;
      }
    }

    // Malware findings
    for (const finding of analysis.malwareFindings) {
      switch (finding.severity) {
        case 'critical': score += 35; break;
        case 'high': score += 20; break;
        case 'medium': score += 10; break;
      }
    }

    // Obfuscation adds to score
    if (analysis.obfuscationAnalysis) {
      score += analysis.obfuscationAnalysis.score * 0.5;
    }

    // Nested JARs are suspicious
    score += analysis.nestedJars.length * 5;

    // Structural findings
    for (const finding of analysis.structuralFindings) {
      if (finding.severity === 'critical') score += 15;
      else if (finding.severity === 'warning') score += 5;
    }

    // Cap at 100
    analysis.threatScore = Math.min(100, Math.round(score));

    // Determine threat level
    if (analysis.threatScore >= 70) {
      analysis.threatLevel = 'critical';
    } else if (analysis.threatScore >= 45) {
      analysis.threatLevel = 'suspicious';
    } else if (analysis.threatScore >= 20) {
      analysis.threatLevel = 'warning';
    } else if (analysis.threatScore > 0) {
      analysis.threatLevel = 'safe';
    } else {
      analysis.threatLevel = 'safe';
    }
  }

  /**
   * Categorize all findings
   */
  categorizeFindings(analysis) {
    const categories = {};

    const addFindings = (matches) => {
      for (const match of matches) {
        const cat = match.category || 'Other';
        if (!categories[cat]) {
          categories[cat] = [];
        }
        categories[cat].push({
          name: match.patternName,
          severity: match.severity,
          file: match.file,
          context: match.context || null,
          type: match.type
        });
      }
    };

    addFindings(analysis.fileMatches);
    addFindings(analysis.stringMatches);

    return categories;
  }

  /**
   * Generate scan summary
   */
  generateSummary() {
    const total = this.results.length;
    const safe = this.results.filter(r => r.verified || r.threatLevel === 'safe').length;
    const suspicious = this.results.filter(r => r.threatLevel === 'suspicious' || r.threatLevel === 'warning').length;
    const critical = this.results.filter(r => r.threatLevel === 'critical').length;
    const obfuscated = this.results.filter(r => r.obfuscationAnalysis?.isObfuscated).length;
    const errors = this.results.filter(r => r.threatLevel === 'error').length;

    return {
      total,
      safe,
      suspicious,
      critical,
      obfuscated,
      errors,
      timestamp: new Date().toISOString()
    };
  }

  formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  emit(channel, data) {
    if (this.webContents && !this.webContents.isDestroyed()) {
      this.webContents.send(channel, data);
    }
  }
}

module.exports = { ModScanner };
