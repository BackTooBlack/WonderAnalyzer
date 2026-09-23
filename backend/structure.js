/**
 * Structural Analysis Module
 * Inspects mod metadata, loader type, package structure, and suspicious patterns
 */

/**
 * Analyze the structural characteristics of a mod
 */
function analyzeStructure(entries, textFiles, analysisData) {
  const findings = [];

  // 1. Detect mod loader type
  const loaderInfo = detectModLoader(entries, textFiles);
  if (loaderInfo) {
    findings.push({
      type: 'mod_loader',
      value: loaderInfo.type,
      severity: 'info',
      message: `Mod loader: ${loaderInfo.type}`,
      details: loaderInfo.details
    });
  }

  // 2. Detect mod ID from metadata
  const modInfo = extractModMetadata(textFiles, entries);
  if (modInfo.modId) {
    findings.push({
      type: 'mod_id',
      value: modInfo.modId,
      severity: 'info',
      message: `Mod ID: ${modInfo.modId}`
    });
  }
  if (modInfo.authors) {
    findings.push({
      type: 'mod_author',
      value: modInfo.authors,
      severity: 'info',
      message: `Author(s): ${modInfo.authors}`
    });
  }

  // 3. Check for suspicious structural patterns
  // Hollow shell detection: minimal outer content wrapping a large inner JAR
  const innerJarEntries = entries.filter(e =>
    e.name.match(/^META-INF\/jars\/.*\.jar$/i)
  );
  const outerClasses = entries.filter(e =>
    e.name.endsWith('.class') && !e.name.startsWith('META-INF')
  );

  if (innerJarEntries.length > 0 && outerClasses.length < 5) {
    findings.push({
      type: 'hollow_shell',
      severity: 'critical',
      message: 'Hollow shell mod detected: minimal outer classes wrapping inner JAR(s)',
      details: `Only ${outerClasses.length} outer class(es) with ${innerJarEntries.length} nested JAR(s)`
    });
  }

  // 4. Suspicious nested JARs without version info
  for (const innerJar of innerJarEntries) {
    const jarName = innerJar.name.split('/').pop();
    if (!/v?\d+\.\d+/.test(jarName) && jarName.length < 10) {
      findings.push({
        type: 'suspicious_nested_jar',
        severity: 'warning',
        message: `Suspicious nested JAR: ${jarName} (no version info)`,
        details: innerJar.name
      });
    }
  }

  // 5. Check for suspicious file locations
  const suspiciousPaths = [
    { regex: /^scripts?\//i, message: 'Script files in root (possible cheat scripts)' },
    { regex: /^natives?\//i, message: 'Native libraries directory' },
    { regex: /^config\/.*cheat/i, message: 'Cheat configuration files' },
    { regex: /^assets\/.*clickgui/i, message: 'ClickGUI assets (cheat client UI)' },
    { regex: /\.sh\b|\.bat\b|\.cmd\b|\.ps1\b/i, message: 'Executable script found' },
    { regex: /^linux\b|^windows\b|^macos\b|^os\//i, message: 'Platform-specific native folder' },
    { regex: /\.so\b|\.dll\b|\.dylib\b|\.jnilib\b/i, message: 'Native binary file' },
  ];

  for (const entry of entries) {
    if (entry.isDirectory) continue;
    for (const { regex, message } of suspiciousPaths) {
      if (regex.test(entry.name)) {
        findings.push({
          type: 'suspicious_path',
          severity: 'warning',
          message,
          details: entry.name
        });
      }
    }
  }

  // 6. Check package depth and structure
  const packages = new Map();
  for (const entry of entries) {
    if (entry.isDirectory || !entry.name.endsWith('.class')) continue;
    const parts = entry.name.split('/');
    if (parts.length > 1) {
      const pkg = parts.slice(0, -1).join('/');
      packages.set(pkg, (packages.get(pkg) || 0) + 1);
    }
  }

  // Detect very deep package nesting (>5 levels)
  for (const [pkg, count] of packages) {
    if (pkg.split('/').length > 6) {
      findings.push({
        type: 'deep_package',
        severity: 'info',
        message: `Deep package nesting: ${pkg}`,
        details: `${count} class(es)`
      });
    }
  }

  // 7. Check for Minecraft version specific directories
  const versionDirs = entries.filter(e =>
    e.isDirectory && /1\.\d+(\.\d+)?/.test(e.name)
  );
  if (versionDirs.length > 0) {
    findings.push({
      type: 'version_dirs',
      severity: 'info',
      message: `Contains version-specific directories: ${versionDirs.map(v => v.name).join(', ')}`
    });
  }

  return findings;
}

/**
 * Detect the mod loader type from entries and content
 */
function detectModLoader(entries, textFiles) {
  const loaderIndicators = {
    'Forge': [
      { file: 'META-INF/MODLIST' },
      { file: 'META-INF/mods.toml' },
      { file: 'META-INF/mcp.mods.cfg' },
      { content: /net\.minecraftforge|ForgeConfigSpec|FMLJavaModLoadingContext/i },
      { content: /@Mod\s*\(/i },
    ],
    'Fabric': [
      { file: 'fabric.mod.json' },
      { content: /fabric-loom|fabricmc/i },
      { content: /net\.fabricmc\.fabric|FabricLoader/i },
    ],
    'NeoForge': [
      { file: 'META-INF/neoforge.mods.toml' },
      { content: /neoforge|NeoForge/i },
      { content: /@Mod\s*\(".*neoforge/i },
    ],
    'Quilt': [
      { file: 'quilt.mod.json' },
      { content: /quiltloader|QuiltLoader/i },
    ],
    'LiteLoader': [
      { file: 'META-INF/litemod.json' },
      { content: /liteloader|LiteLoader/i },
    ],
  };

  const fileNames = new Set(entries.map(e => e.name));
  const allContent = textFiles.map(t => t.content).join('\n');

  for (const [loader, indicators] of Object.entries(loaderIndicators)) {
    for (const indicator of indicators) {
      if (indicator.file && fileNames.has(indicator.file)) {
        return { type: loader, details: `Found ${indicator.file}` };
      }
      if (indicator.content && indicator.content.test(allContent)) {
        return { type: loader, details: `Content matched ${indicator.content}` };
      }
    }
  }

  return null;
}

/**
 * Extract mod metadata from manifest and config files
 */
function extractModMetadata(textFiles, entries) {
  const result = {
    modId: null,
    authors: null,
    version: null,
    description: null
  };

  // Try to get mod ID from fabric.mod.json
  for (const { file, content } of textFiles) {
    if (file === 'fabric.mod.json') {
      try {
        // Simple JSON extraction (avoid dependency on JSON.parse for malformed JSON)
        const idMatch = content.match(/"id"\s*:\s*"([^"]+)"/);
        const authorMatch = content.match(/"authors"\s*:\s*\["?([^"\]]+)"?\]/);
        if (idMatch) result.modId = idMatch[1];
        if (authorMatch) result.authors = authorMatch[1];
      } catch (e) {}
    }

    // Try mods.toml (Forge/NeoForge)
    if (file === 'META-INF/mods.toml' || file === 'META-INF/neoforge.mods.toml') {
      const idMatch = content.match(/modId\s*=\s*"?([^"\n]+)"?/);
      const authorMatch = content.match(/authors\s*=\s*"?([^"\n"]+)"?/);
      if (idMatch) result.modId = idMatch[1];
      if (authorMatch) result.authors = authorMatch[1];
    }

    // Try MANIFEST.MF
    if (file.toUpperCase() === 'META-INF/MANIFEST.MF') {
      const authorMatch = content.match(/Created-By:\s*(.+)/i);
      if (authorMatch) result.authors = result.authors || authorMatch[1].trim();
    }
  }

  return result;
}

module.exports = { analyzeStructure };
