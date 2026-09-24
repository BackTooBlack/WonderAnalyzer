/**
 * Detail View Renderer
 * Renders the full analysis breakdown for a mod in the modal
 */

(function() {
  'use strict';

  window.renderDetail = function(analysis) {
    const dom = window.appDom;

    // Set modal header
    dom.modalTitle.textContent = analysis.name;

    // Set threat badge
    const badge = dom.modalThreatBadge;
    if (analysis.verified) {
      badge.textContent = '✅ VERIFIED SAFE';
      badge.className = 'modal-threat-badge';
      badge.style.cssText = 'background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3);';
    } else {
      switch (analysis.threatLevel) {
        case 'critical':
          badge.textContent = '🚨 CRITICAL THREAT';
          badge.style.cssText = 'background: rgba(255,59,92,0.15); color: #ff3b5c; border: 1px solid rgba(255,59,92,0.3);';
          break;
        case 'suspicious':
          badge.textContent = '⚠️ SUSPICIOUS';
          badge.style.cssText = 'background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3);';
          break;
        case 'warning':
          badge.textContent = '🟡 WARNING';
          badge.style.cssText = 'background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3);';
          break;
        case 'info':
          if (analysis.modId === 'client') {
            badge.textContent = '✅ OFFICIAL CLIENT';
            badge.style.cssText = 'background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3);';
          } else if (analysis.modId === 'report') {
            badge.textContent = 'ℹ️ DIAGNOSTIC REPORT';
            badge.style.cssText = 'background: rgba(148,163,184,0.15); color: #94a3b8; border: 1px solid rgba(148,163,184,0.3);';
          } else {
            badge.textContent = '💎 OPTIMIZER';
            badge.style.cssText = 'background: rgba(0,240,255,0.12); color: #22d3ee; border: 1px solid rgba(0,240,255,0.3);';
          }
          break;
        case 'error':
          badge.textContent = '❓ ANALYSIS ERROR';
          badge.style.cssText = 'background: rgba(100,100,120,0.15); color: #9595a8; border: 1px solid rgba(100,100,120,0.3);';
          break;
        default:
          badge.textContent = '✅ SAFE';
          badge.style.cssText = 'background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3);';
      }
    }

    // Build body content
    let html = '';

    // Threat Meter
    html += renderThreatMeter(analysis);

    // Basic Info
    html += renderBasicInfo(analysis);

    // Obfuscation Analysis
    if (analysis.obfuscationAnalysis && analysis.obfuscationAnalysis.score > 0) {
      html += renderObfuscation(analysis.obfuscationAnalysis);
    }

    // Threats Found (Categorized)
    const categories = analysis.categories || {};
    if (Object.keys(categories).length > 0) {
      html += renderThreatCategories(categories);
    }

    // Malware Findings
    if (analysis.malwareFindings && analysis.malwareFindings.length > 0) {
      html += renderMalwareFindings(analysis.malwareFindings);
    }

    // Fullwidth Unicode
    if (analysis.fullwidthStrings && analysis.fullwidthStrings.length > 0) {
      html += renderFullwidthStrings(analysis.fullwidthStrings);
    }

    // Structural Findings
    if (analysis.structuralFindings && analysis.structuralFindings.length > 0) {
      html += renderStructuralFindings(analysis.structuralFindings);
    }

    // Error info
    if (analysis.error) {
      html += renderError(analysis.error);
    }

    dom.modalBody.innerHTML = html;
  };

  // ===== Threat Meter =====
  function renderThreatMeter(analysis) {
    const score = analysis.threatScore || 0;
    const level = analysis.threatLevel || 'safe';
    const color = getScoreColor(score);
    const circumference = 2 * Math.PI * 34;
    const offset = circumference - (score / 100) * circumference;

    let label, desc;
    switch (level) {
      case 'critical':
        label = 'Critical Threat';
        desc = 'This mod contains multiple high-severity cheat modules or malware indicators. Immediate attention recommended.';
        break;
      case 'suspicious':
        label = 'Suspicious';
        desc = 'This mod contains suspicious patterns that may indicate cheat functionality or deceptive behavior.';
        break;
      case 'warning':
        label = 'Warning';
        desc = 'Some suspicious patterns were detected. Further investigation may be needed.';
        break;
      case 'info':
        if (analysis.modId === 'client') {
          label = 'Official Client File';
          desc = 'This file ships with a verified Minecraft client (Feather, Lunar, Badlion or LabyMod). Matches are shown as an official-client mention and can never flag as a cheat.';
        } else if (analysis.modId === 'report') {
          label = 'Diagnostic Report';
          desc = 'This is a crash/diagnostic file. Any signature matches inside it are mentions only — crash reports are never flagged as cheat configs.';
        } else {
          label = 'Optimizer';
          desc = 'A known performance optimizer was detected. It is not a cheat — this entry only tells you which optimizer is in use.';
        }
        break;
      default:
        label = 'Clean';
        desc = 'No significant threats detected. This mod appears to be safe.';
    }

    return `
      <div class="detail-section">
        <div class="threat-meter">
          <div class="threat-meter-gauge">
            <svg width="80" height="80" viewBox="0 0 80 80">
              <circle cx="40" cy="40" r="34" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="6"/>
              <circle cx="40" cy="40" r="34" fill="none" stroke="${color}" stroke-width="6"
                stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
                stroke-linecap="round" style="transition: stroke-dashoffset 1s ease;"/>
            </svg>
            <div class="threat-meter-value" style="color: ${color}">${score}</div>
          </div>
          <div class="threat-meter-info">
            <div class="threat-meter-label" style="color: ${color}">${label}</div>
            <div class="threat-meter-desc">${desc}</div>
          </div>
        </div>
      </div>
    `;
  }

  // ===== Basic Info =====
  function renderBasicInfo(analysis) {
    const items = [
      { label: 'File Name', value: analysis.name },
      { label: 'File Size', value: analysis.sizeFormatted || formatSize(analysis.size) },
    ];

    if (analysis.path) items.push({ label: 'Location', value: analysis.path });

    if (analysis.isConfigScan) {
      // %APPDATA% cheat config finding - mod metadata doesn't apply
      items.push({ label: 'Detected As', value: analysis.modLoader || 'Cheat Config' });
      items.push({ label: 'Signatures Matched', value: String(analysis.stringMatches?.length || 0) });
      return renderInfoGrid(items);
    }

    items.push({ label: 'Mod Loader', value: analysis.modLoader || 'Unknown' });

    if (analysis.modId) items.push({ label: 'Mod ID', value: analysis.modId });
    if (analysis.modVersion) items.push({ label: 'Version', value: analysis.modVersion });
    if (analysis.modAuthor) items.push({ label: 'Author', value: analysis.modAuthor });
    if (analysis.hash) items.push({ label: 'SHA-1 Hash', value: analysis.hash, mono: true });

    if (analysis.verified) {
      items.push({ label: 'Verification', value: `✅ Verified via ${analysis.verificationSource}`, color: 'var(--safe-color)' });
    } else {
      items.push({ label: 'Verification', value: '❓ Not in database (unknown mod)' });
    }

    items.push({ label: 'Total Files', value: String(analysis.totalFiles || 0) });
    items.push({ label: 'Class Files', value: String(analysis.totalClasses || 0) });

    return renderInfoGrid(items);
  }

  // Shared grid renderer for the Basic Information section
  function renderInfoGrid(items) {
    return `
      <div class="detail-section">
        <div class="detail-section-title">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
          </svg>
          Basic Information
        </div>
        <div class="detail-grid">
          ${items.map(item => `
            <div class="detail-item">
              <div class="detail-item-label">${item.label}</div>
              <div class="detail-item-value${item.mono ? ' mono' : ''}" ${item.color ? `style="color: ${item.color}"` : ''}>
                ${escapeHtml(item.value)}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // ===== Obfuscation =====
  function renderObfuscation(obf) {
    const score = obf.score;
    const color = score > 60 ? 'var(--critical-color)' : score > 30 ? 'var(--warning-color)' : 'var(--safe-color)';
    const circumference = 2 * Math.PI * 28;
    const offset = circumference - (score / 100) * circumference;

    let indicatorHtml = '';
    if (obf.indicators && obf.indicators.length > 0) {
      indicatorHtml = obf.indicators.map(ind => `
        <div class="category-item">
          <div class="category-item-dot ${ind.severity}"></div>
          <div class="category-item-text">
            <div class="category-item-name">${escapeHtml(ind.message)}</div>
          </div>
        </div>
      `).join('');
    }

    // Class naming stats
    let statsHtml = '';
    if (obf.classNamingAnalysis) {
      const cn = obf.classNamingAnalysis;
      statsHtml = `
        <div class="detail-grid" style="margin-top: 12px;">
          <div class="detail-item">
            <div class="detail-item-label">Total Classes</div>
            <div class="detail-item-value">${cn.total}</div>
          </div>
          <div class="detail-item">
            <div class="detail-item-label">Single-Letter Names</div>
            <div class="detail-item-value" style="color: ${cn.singleLetterRatio > 0.3 ? 'var(--critical-color)' : 'var(--text-primary)'}">
              ${cn.singleLetter} (${Math.round(cn.singleLetterRatio * 100)}%)
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-item-label">Numeric Names</div>
            <div class="detail-item-value" style="color: ${cn.numericRatio > 0.1 ? 'var(--critical-color)' : 'var(--text-primary)'}">
              ${cn.numeric} (${Math.round(cn.numericRatio * 100)}%)
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-item-label">Unicode Names</div>
            <div class="detail-item-value" style="color: ${cn.unicodeRatio > 0.05 ? 'var(--critical-color)' : 'var(--text-primary)'}">
              ${cn.unicode} (${Math.round(cn.unicodeRatio * 100)}%)
            </div>
          </div>
        </div>
      `;
    }

    // Obfuscator signatures
    let sigHtml = '';
    if (obf.obfuscatorSignatures && obf.obfuscatorSignatures.length > 0) {
      sigHtml = `
        <div style="margin-top: 8px;">
          <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">Detected Obfuscators:</div>
          ${obf.obfuscatorSignatures.map(s => `
            <span class="threat-tag" style="display: inline-flex; margin-right: 4px;">${s.name}</span>
          `).join('')}
        </div>
      `;
    }

    return `
      <div class="detail-section">
        <div class="detail-section-title">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          Obfuscation Analysis
          <span style="font-size: 12px; color: ${color}; margin-left: auto; font-weight: 600;">${score}/100</span>
        </div>
        <div style="display: flex; align-items: center; gap: 16px; padding: 12px; background: rgba(255,255,255,0.02); border: 1px solid var(--border-glass); border-radius: var(--radius-md);">
          <div style="position: relative; width: 64px; height: 64px; flex-shrink: 0;">
            <svg width="64" height="64" viewBox="0 0 64 64">
              <circle cx="32" cy="32" r="28" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="5"/>
              <circle cx="32" cy="32" r="28" fill="none" stroke="${color}" stroke-width="5"
                stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
                stroke-linecap="round" style="transform: rotate(-90deg); transform-origin: center; transition: stroke-dashoffset 1s ease;"/>
            </svg>
            <div style="position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 18px; font-weight: 700; font-family: var(--font-mono); color: ${color};">
              ${score}
            </div>
          </div>
          <div>
            <div style="font-size: 14px; font-weight: 600; color: ${color}; margin-bottom: 2px;">
              ${score > 60 ? 'Heavily Obfuscated' : score > 30 ? 'Moderately Obfuscated' : score > 10 ? 'Lightly Obfuscated' : 'Minimal Obfuscation'}
            </div>
            <div style="font-size: 12px; color: var(--text-secondary);">
              ${obf.indicators?.length || 0} indicator(s) detected
            </div>
          </div>
        </div>
        ${indicatorHtml ? `<div class="category-group-items" style="margin-top: 8px;">${indicatorHtml}</div>` : ''}
        ${statsHtml}
        ${sigHtml}
      </div>
    `;
  }

  // ===== Threat Categories =====
  function renderThreatCategories(categories) {
    const categoryHtml = Object.entries(categories).map(([catName, items]) => {
      const itemsHtml = items.map(item => `
        <div class="category-item">
          <div class="category-item-dot ${item.severity}"></div>
          <div class="category-item-text">
            <div class="category-item-name">${escapeHtml(item.name)}</div>
            ${item.file ? `<div class="category-item-file">📁 ${escapeHtml(item.file)}</div>` : ''}
            ${item.context ? `<div class="category-item-context">${escapeHtml(item.context)}</div>` : ''}
          </div>
        </div>
      `).join('');

      return `
        <div class="category-group">
          <div class="category-group-header" onclick="this.parentElement.querySelector('.category-group-items').style.display = this.parentElement.querySelector('.category-group-items').style.display === 'none' ? 'flex' : 'none'">
            <div class="category-group-name">${escapeHtml(catName)}</div>
            <div class="category-group-count">${items.length}</div>
          </div>
          <div class="category-group-items">
            ${itemsHtml}
          </div>
        </div>
      `;
    }).join('');

    return `
      <div class="detail-section">
        <div class="detail-section-title">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          Threats Detected
        </div>
        <div class="category-list">
          ${categoryHtml}
        </div>
      </div>
    `;
  }

  // ===== Malware Findings =====
  function renderMalwareFindings(findings) {
    const itemsHtml = findings.map(f => `
      <div class="category-item">
        <div class="category-item-dot ${f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'high' : 'medium'}"></div>
        <div class="category-item-text">
          <div class="category-item-name">${escapeHtml(f.name)}</div>
          <div class="category-item-file">📁 ${escapeHtml(f.file)}</div>
          ${f.context ? `<div class="category-item-context">${escapeHtml(f.context)}</div>` : ''}
        </div>
      </div>
    `).join('');

    return `
      <div class="detail-section">
        <div class="detail-section-title">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          🦠 Malware & Dangerous Behavior
          <span style="font-size: 12px; color: var(--critical-color); margin-left: auto;">${findings.length} finding(s)</span>
        </div>
        <div class="category-group-items">
          ${itemsHtml}
        </div>
      </div>
    `;
  }

  // ===== Fullwidth Unicode =====
  function renderFullwidthStrings(strings) {
    const itemsHtml = strings.map(s => `
      <div class="category-item">
        <div class="category-item-dot critical"></div>
        <div class="category-item-text">
          <div class="category-item-name">Fullwidth text detected</div>
          <div class="category-item-file">📁 ${escapeHtml(s.file)}</div>
          <div class="category-item-context">Raw: ${escapeHtml(s.raw)} → Decoded: ${escapeHtml(s.decoded)}</div>
        </div>
      </div>
    `).join('');

    return `
      <div class="detail-section">
        <div class="detail-section-title">
          🔠 Fullwidth Unicode Strings
          <span style="font-size: 12px; color: var(--critical-color); margin-left: auto;">${strings.length} found</span>
        </div>
        <div class="category-group-items">
          ${itemsHtml}
        </div>
      </div>
    `;
  }

  // ===== Structural Findings =====
  function renderStructuralFindings(findings) {
    const itemsHtml = findings.map(f => {
      const sevClass = f.severity === 'critical' ? 'critical' : f.severity === 'warning' ? 'high' : 'info';
      return `
        <div class="category-item">
          <div class="category-item-dot ${sevClass}"></div>
          <div class="category-item-text">
            <div class="category-item-name">${escapeHtml(f.message)}</div>
            ${f.details ? `<div class="category-item-file">${escapeHtml(f.details)}</div>` : ''}
          </div>
        </div>
      `;
    }).join('');

    return `
      <div class="detail-section">
        <div class="detail-section-title">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
          </svg>
          Structural Analysis
        </div>
        <div class="category-group-items">
          ${itemsHtml}
        </div>
      </div>
    `;
  }

  // ===== Error =====
  function renderError(error) {
    return `
      <div class="detail-section">
        <div class="detail-section-title" style="color: var(--critical-color);">
          ❌ Analysis Error
        </div>
        <div style="padding: 12px; background: rgba(255,59,92,0.05); border: 1px solid rgba(255,59,92,0.15); border-radius: var(--radius-md); font-size: 13px; color: var(--text-secondary);">
          ${escapeHtml(error)}
        </div>
      </div>
    `;
  }

  // ===== Helpers =====
  function getScoreColor(score) {
    if (score >= 70) return '#ff3b5c';
    if (score >= 45) return '#f97316';
    if (score >= 20) return '#f59e0b';
    return '#10b981';
  }

  function formatSize(bytes) {
    if (!bytes) return 'Unknown';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

})();
