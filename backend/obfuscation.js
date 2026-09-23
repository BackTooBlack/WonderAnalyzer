/**
 * Obfuscation Detection Engine
 * Identifies obfuscated mods and known obfuscator signatures
 */

const { CHEAT_PATTERNS } = require('./patterns');

/**
 * Analyze file entries and content for obfuscation indicators
 */
function analyzeObfuscation(entries, textFiles) {
  const result = {
    isObfuscated: false,
    score: 0,
    indicators: [],
    obfuscatorSignatures: [],
    classNamingAnalysis: null,
    packageAnalysis: null,
    details: []
  };

  const classFiles = entries.filter(e => e.name.endsWith('.class') && !e.isDirectory);
  const totalClasses = classFiles.length;

  if (totalClasses === 0) {
    result.score = 0;
    return result;
  }

  // 1. Analyze class file names
  const classNaming = analyzeClassNames(classFiles);
  result.classNamingAnalysis = classNaming;

  // 2. Analyze package structure
  const packageAnalysis = analyzePackages(entries);
  result.packageAnalysis = packageAnalysis;

  // 3. Detect known obfuscator signatures
  const obfSignatures = detectObfuscatorSignatures(textFiles);
  result.obfuscatorSignatures = obfSignatures;

  // 4. Calculate obfuscation score
  let score = 0;

  // Single-letter class names
  if (classNaming.singleLetterRatio > 0.3) {
    score += classNaming.singleLetterRatio * 30;
    result.indicators.push({
      type: 'single_letter_classes',
      severity: 'high',
      message: `${Math.round(classNaming.singleLetterRatio * 100)}% of classes use single-letter names`
    });
  }

  // Very short class names (2 letters)
  if (classNaming.shortNameRatio > 0.5) {
    score += classNaming.shortNameRatio * 25;
    result.indicators.push({
      type: 'short_class_names',
      severity: 'medium',
      message: `${Math.round(classNaming.shortNameRatio * 100)}% of classes have names ≤2 characters`
    });
  }

  // Numeric class names
  if (classNaming.numericRatio > 0.1) {
    score += classNaming.numericRatio * 25;
    result.indicators.push({
      type: 'numeric_class_names',
      severity: 'high',
      message: `${Math.round(classNaming.numericRatio * 100)}% of classes use numeric names`
    });
  }

  // Unicode class names
  if (classNaming.unicodeRatio > 0.05) {
    score += classNaming.unicodeRatio * 30;
    result.indicators.push({
      type: 'unicode_class_names',
      severity: 'critical',
      message: `${Math.round(classNaming.unicodeRatio * 100)}% of classes use Unicode names`
    });
  }

  // Single-letter package paths
  if (packageAnalysis.singleLetterPackageRatio > 0.5) {
    score += packageAnalysis.singleLetterPackageRatio * 20;
    result.indicators.push({
      type: 'single_letter_packages',
      severity: 'medium',
      message: `${Math.round(packageAnalysis.singleLetterPackageRatio * 100)}% of packages use single-letter names`
    });
  }

  // Deep nesting with single-letter names
  if (packageAnalysis.deepObfuscatedPaths > 0) {
    score += packageAnalysis.deepObfuscatedPaths * 3;
    result.indicators.push({
      type: 'deep_obfuscated_paths',
      severity: 'medium',
      message: `Found ${packageAnalysis.deepObfuscatedPaths} deeply nested obfuscated package paths`
    });
  }

  // Known obfuscator signatures
  if (obfSignatures.length > 0) {
    score += obfSignatures.length * 15;
    for (const sig of obfSignatures) {
      result.indicators.push({
        type: 'obfuscator_signature',
        severity: 'high',
        message: `Detected ${sig.name} obfuscator signature`
      });
    }
  }

  // Gibberish names (high consonant ratio without vowels)
  if (classNaming.gibberishRatio > 0.2) {
    score += classNaming.gibberishRatio * 15;
    result.indicators.push({
      type: 'gibberish_names',
      severity: 'medium',
      message: `${Math.round(classNaming.gibberishRatio * 100)}% of classes appear to have gibberish names`
    });
  }

  result.score = Math.min(100, Math.round(score));
  result.isObfuscated = result.score > 25;

  return result;
}

/**
 * Analyze class file naming patterns
 */
function analyzeClassNames(classFiles) {
  let singleLetter = 0;
  let shortNames = 0; // <=2 chars
  let numeric = 0;
  let unicode = 0;
  let gibberish = 0;
  const total = classFiles.length;

  for (const file of classFiles) {
    const name = file.name.split('/').pop().replace('.class', '');

    // Single letter names
    if (name.length === 1) {
      singleLetter++;
      shortNames++;
    }
    // Short names
    else if (name.length <= 2) {
      shortNames++;
    }

    // Numeric names
    if (/^\d+$/.test(name)) {
      numeric++;
    }

    // Unicode names (non-ASCII)
    if (/[^a-zA-Z0-9$_]/.test(name)) {
      unicode++;
    }

    // Gibberish: high consonant clusters without vowels
    if (name.length > 2 && /^[bcdfghjklmnpqrstvwxyz]{2,}$/i.test(name)) {
      gibberish++;
    }
  }

  return {
    singleLetterRatio: total > 0 ? singleLetter / total : 0,
    shortNameRatio: total > 0 ? shortNames / total : 0,
    numericRatio: total > 0 ? numeric / total : 0,
    unicodeRatio: total > 0 ? unicode / total : 0,
    gibberishRatio: total > 0 ? gibberish / total : 0,
    total,
    singleLetter,
    shortNames,
    numeric,
    unicode,
    gibberish
  };
}

/**
 * Analyze package directory structure
 */
function analyzePackages(entries) {
  const packages = new Set();
  let singleLetterPackages = 0;
  let deepObfuscated = 0;

  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const parts = entry.name.split('/');
    if (parts.length > 1) {
      packages.add(parts.slice(0, -1).join('/'));
    }
  }

  for (const pkg of packages) {
    const segments = pkg.split('/');
    // Check if all segments are single-letter
    const allSingle = segments.every(s => s.length === 1 && /^[a-z]$/.test(s));
    if (allSingle && segments.length > 1) {
      singleLetterPackages++;
    }
    // Deep nesting with short segments
    if (segments.length > 3 && segments.every(s => s.length <= 2)) {
      deepObfuscated++;
    }
  }

  return {
    totalPackages: packages.size,
    singleLetterPackageRatio: packages.size > 0 ? singleLetterPackages / packages.size : 0,
    deepObfuscatedPaths: deepObfuscated
  };
}

/**
 * Detect known obfuscator signatures in text content
 */
function detectObfuscatorSignatures(textFiles) {
  const signatures = [];
  const obfuscatorPatterns = CHEAT_PATTERNS.obfuscation_signatures.patterns;

  for (const { content } of textFiles) {
    if (!content) continue;
    for (const pattern of obfuscatorPatterns) {
      if (pattern.regex.test(content)) {
        signatures.push({
          name: pattern.name,
          severity: pattern.severity
        });
      }
    }
  }

  // Deduplicate
  return [...new Map(signatures.map(s => [s.name, s])).values()];
}

module.exports = { analyzeObfuscation };
