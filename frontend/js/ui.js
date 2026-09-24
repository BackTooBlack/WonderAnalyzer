/**
 * UI Rendering Engine
 * Handles rendering of mod cards into the grid
 */

(function() {
  'use strict';

  /**
   * Render mod cards into the grid
   */
  window.renderModCards = function(results, gridEl, emptyHtml) {
    const grid = gridEl || window.appDom.modGrid;
    grid.innerHTML = '';

    if (!results || results.length === 0) {
      grid.innerHTML = emptyHtml || `
        <div class="empty-state" style="grid-column: 1 / -1;">
          <div class="empty-state-icon">🔍</div>
          <div class="empty-state-title">No mods found</div>
          <div class="empty-state-desc">No mods match your current filter</div>
        </div>
      `;
      return;
    }

    results.forEach((mod, index) => {
      const card = createModCard(mod, index);
      grid.appendChild(card);
    });
  };

  /**
   * Create a single mod card element
   */
  function createModCard(mod, index) {
    const card = document.createElement('div');
    card.className = `mod-card threat-${getCardThreatClass(mod)}`;
    card.style.animationDelay = `${Math.min(index * 0.02, 0.3)}s`;

    card.innerHTML = `
      <div class="mod-card-header">
        <div class="mod-card-name">
          ${escapeHtml(mod.name)}
          <span>${mod.sizeFormatted || formatSize(mod.size)}</span>
        </div>
        ${createThreatBadge(mod)}
      </div>
      ${createThreatScoreBar(mod)}
      <div class="mod-card-meta">
        ${createMetaTags(mod)}
      </div>
      ${createCategoryChips(mod)}
      ${createThreatTags(mod)}
    `;

    card.addEventListener('click', () => {
      window.showModal(mod);
    });

    return card;
  }

  function getCardThreatClass(mod) {
    if (mod.threatLevel === 'critical') return 'critical';
    if (mod.threatLevel === 'suspicious') return 'suspicious';
    if (mod.threatLevel === 'warning') return 'warning';
    if (mod.threatLevel === 'info') return 'info';
    if (mod.obfuscationAnalysis?.isObfuscated) return 'obfuscated';
    return 'safe';
  }

  function createThreatBadge(mod) {
    let label, className;
    if (mod.verified) {
      label = '✅ VERIFIED';
      className = 'safe';
    } else {
      switch (mod.threatLevel) {
        case 'critical':
          label = '🚨 CRITICAL';
          className = 'critical';
          break;
        case 'suspicious':
          label = '⚠️ SUSPICIOUS';
          className = 'suspicious';
          break;
        case 'warning':
          label = '🟡 WARNING';
          className = 'warning';
          break;
        case 'info':
          // Info mentions carry their own story: optimizer / official client /
          // diagnostic report — never a threat.
          if (mod.modId === 'client') {
            label = '✅ OFFICIAL';
            className = 'info';
          } else if (mod.modId === 'report') {
            label = 'ℹ️ REPORT';
            className = 'info';
          } else if (mod.modId === 'artifact') {
            label = '🎮 ARTIFACT';
            className = 'info';
          } else {
            label = '💎 OPTIMIZER';
            className = 'info';
          }
          break;
        case 'error':
          label = '❓ ERROR';
          className = 'error';
          break;
        default:
          label = '✅ SAFE';
          className = 'safe';
      }
    }

    if (mod.obfuscationAnalysis?.isObfuscated && className === 'safe') {
      label = '🔒 OBFUSCATED';
      className = 'obfuscated';
    }

    return `<div class="threat-badge ${className}">${label}</div>`;
  }

  function createThreatScoreBar(mod) {
    if (mod.threatScore === undefined || mod.threatScore === null) return '';
    const scoreColor = getScoreColor(mod.threatScore);

    return `
      <div class="threat-score">
        <div class="threat-score-header">
          <span class="threat-score-label">Threat Score</span>
          <span class="threat-score-value" style="color: ${scoreColor}">${mod.threatScore}/100</span>
        </div>
        <div class="threat-bar">
          <div class="threat-bar-fill" style="width: ${mod.threatScore}%; background: ${scoreColor};"></div>
        </div>
      </div>
    `;
  }

  function createMetaTags(mod) {
    const tags = [];

    if (mod.modLoader && mod.modLoader !== 'Unknown') {
      tags.push(`<div class="meta-tag">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        ${mod.modLoader}
      </div>`);
    }

    if (mod.modId) {
      tags.push(`<div class="meta-tag">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        ${mod.modId}
      </div>`);
    }

    if (mod.totalFiles > 0) {
      tags.push(`<div class="meta-tag">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        ${mod.totalFiles} files
      </div>`);
    }

    if (mod.totalClasses > 0) {
      tags.push(`<div class="meta-tag">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        ${mod.totalClasses} classes
      </div>`);
    }

    if (mod.verificationSource) {
      tags.push(`<div class="meta-tag" style="color: var(--safe-color);">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        ${mod.verificationSource}
      </div>`);
    }

    return tags.join('');
  }

  function createThreatTags(mod) {
    const threatCount = (mod.fileMatches?.length || 0) +
                       (mod.stringMatches?.length || 0) +
                       (mod.malwareFindings?.length || 0);

    if (threatCount === 0) return '';

    const tags = [];
    const maxTags = 4;

    // Show unique threat names
    const threatNames = new Set();
    const addThreat = (list, severity) => {
      if (!list) return;
      for (const item of list) {
        if (threatNames.size >= maxTags) break;
        const name = item.patternName || item.name;
        if (!threatNames.has(name)) {
          threatNames.add(name);
          const severityClass = (severity === 'critical') ? '' : (severity === 'high' || severity === 'warning') ? 'warning' : 'info';
          tags.push(`<span class="threat-tag ${severityClass}">${name}</span>`);
        }
      }
    };

    addThreat(mod.fileMatches, 'critical');
    addThreat(mod.stringMatches, 'high');
    addThreat(mod.malwareFindings, 'critical');

    if (threatCount > maxTags) {
      tags.push(`<span class="threat-tag info">+${threatCount - maxTags} more</span>`);
    }

    return `<div class="mod-card-threats">${tags.join('')}</div>`;
  }

  /**
   * APPDATA-checker findings carry a `categories` map keyed by category —
   * show each flag's category as a chip so the row explains WHY it flagged.
   */
  function createCategoryChips(mod) {
    if (!mod.isConfigScan || !mod.categories) return '';
    const keys = Object.keys(mod.categories);
    if (keys.length === 0) return '';
    return `<div class="mod-card-cats">${keys
      .map(k => `<span class="cat-chip">${escapeHtml(k)}</span>`)
      .join('')}</div>`;
  }

  function getScoreColor(score) {
    if (score >= 70) return 'var(--critical-color)';
    if (score >= 45) return 'var(--suspicious-color)';
    if (score >= 20) return 'var(--warning-color)';
    return 'var(--safe-color)';
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
