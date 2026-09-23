/**
 * WonderAnalyzer - Main Application Controller
 */

(function() {
  'use strict';

  // ===== App State =====
  const state = {
    selectedPath: null,
    selectedModCount: 0,
    scanResults: null,
    scanSummary: null,
    currentFilter: 'all',
    searchQuery: '',
    scanning: false,
    scanMode: 'mods',
    configResults: null,
    configSummary: null,
    configQuery: '',
  };

  // ===== DOM References =====
  const dom = {
    screens: {
      home: document.getElementById('screen-home'),
      scanning: document.getElementById('screen-scanning'),
      results: document.getElementById('screen-results'),
      configResults: document.getElementById('screen-config-results'),
    },
    // Home
    dropZone: document.getElementById('drop-zone'),
    folderInput: document.getElementById('folder-input'),
    pathDisplay: document.getElementById('path-display'),
    pathText: document.getElementById('path-text'),
    modCount: document.getElementById('mod-count'),
    btnClear: document.getElementById('btn-clear'),
    btnDefaultPath: document.getElementById('btn-default-path'),
    btnScan: document.getElementById('btn-scan'),
    btnConfigScan: document.getElementById('btn-config-scan'),
    configPathDisplay: document.getElementById('config-path-display'),
    configPathText: document.getElementById('config-path-text'),
    // Scanning
    scanTitle: document.getElementById('scan-title'),
    scanPhase: document.getElementById('scan-phase'),
    scanProgressFill: document.getElementById('scan-progress-fill'),
    scanCounter: document.getElementById('scan-counter'),
    scanPercent: document.getElementById('scan-percent'),
    scanCurrentFile: document.getElementById('scan-current-file'),
    statTotal: document.getElementById('stat-total'),
    statSafe: document.getElementById('stat-safe'),
    statWarning: document.getElementById('stat-warning'),
    statCritical: document.getElementById('stat-critical'),
    btnAbort: document.getElementById('btn-abort'),
    // Results
    resultsTime: document.getElementById('results-time'),
    sumTotal: document.getElementById('sum-total'),
    sumSafe: document.getElementById('sum-safe'),
    sumWarning: document.getElementById('sum-warning'),
    sumCritical: document.getElementById('sum-critical'),
    sumObfuscated: document.getElementById('sum-obfuscated'),
    filterAll: document.getElementById('filter-all'),
    filterCritical: document.getElementById('filter-critical'),
    filterSuspicious: document.getElementById('filter-suspicious'),
    filterWarning: document.getElementById('filter-warning'),
    filterSafe: document.getElementById('filter-safe'),
    filterObfuscated: document.getElementById('filter-obfuscated'),
    modGrid: document.getElementById('mod-grid'),
    btnBack: document.getElementById('btn-back'),
    resultsSearch: document.getElementById('results-search'),
    // Config results
    configResultsTime: document.getElementById('config-results-time'),
    cfgSumScanned: document.getElementById('cfg-sum-scanned'),
    cfgSumClean: document.getElementById('cfg-sum-clean'),
    cfgSumFound: document.getElementById('cfg-sum-found'),
    cfgSumCritical: document.getElementById('cfg-sum-critical'),
    cfgSumWarning: document.getElementById('cfg-sum-warning'),
    configGrid: document.getElementById('config-grid'),
    btnConfigBack: document.getElementById('btn-config-back'),
    configSearch: document.getElementById('config-search'),
    configLaunchers: document.getElementById('config-launchers'),
    // Modal
    modalOverlay: document.getElementById('modal-overlay'),
    modalTitle: document.getElementById('modal-title'),
    modalThreatBadge: document.getElementById('modal-threat-badge'),
    modalBody: document.getElementById('modal-body'),
    modalClose: document.getElementById('modal-close'),
    // Titlebar
    btnMinimize: document.getElementById('btn-minimize'),
    btnMaximize: document.getElementById('btn-maximize'),
    btnClose: document.getElementById('btn-close'),
  };

  // ===== Screen Navigation =====
  function showScreen(name) {
    Object.values(dom.screens).forEach(s => s.classList.remove('active'));
    if (dom.screens[name]) {
      dom.screens[name].classList.add('active');
    }
  }

  // ===== Title Bar Controls =====
  dom.btnMinimize.addEventListener('click', () => window.electronAPI?.windowMinimize());
  dom.btnMaximize.addEventListener('click', () => window.electronAPI?.windowMaximize());
  dom.btnClose.addEventListener('click', () => window.electronAPI?.windowClose());

  // ===== Directory Selection =====
  dom.dropZone.addEventListener('click', async () => {
    const dir = await window.electronAPI.selectDirectory();
    if (dir) {
      await handleDirectorySelected(dir);
    }
  });

  dom.folderInput.addEventListener('change', async (e) => {
    if (e.target.files.length > 0) {
      const firstFile = e.target.files[0];
      // Try to extract directory path from webkitRelativePath
      const path = firstFile.webkitRelativePath;
      if (path) {
        const parts = path.split('/');
        parts.pop(); // Remove filename
        await handleDirectorySelected('/' + parts.join('/'));
      }
    }
  });

  dom.btnClear.addEventListener('click', () => {
    state.selectedPath = null;
    state.selectedModCount = 0;
    dom.pathDisplay.style.display = 'none';
    dom.dropZone.style.display = 'block';
    dom.btnScan.disabled = true;
  });

  dom.btnDefaultPath.addEventListener('click', async () => {
    const defaultInfo = await window.electronAPI.getDefaultModsPath();
    if (defaultInfo.exists) {
      await handleDirectorySelected(defaultInfo.path);
    } else {
      alert(`Default mods path not found:\n${defaultInfo.path}\n\nPlease select your mods folder manually.`);
    }
  });

  async function handleDirectorySelected(dirPath) {
    state.selectedPath = dirPath;
    dom.pathText.textContent = dirPath;
    dom.pathDisplay.style.display = 'flex';
    dom.dropZone.style.display = 'none';
    dom.btnScan.disabled = false;
  }
  // Exposed for the Tauri bridge (native drag & drop gives us real paths)
  window.__setSelectedDirectory = handleDirectorySelected;

  // Drag & Drop
  dom.dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dom.dropZone.classList.add('drag-over');
  });

  dom.dropZone.addEventListener('dragleave', () => {
    dom.dropZone.classList.remove('drag-over');
  });

  dom.dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dom.dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
      const path = e.dataTransfer.files[0].path;
      if (path) {
        handleDirectorySelected(path);
      }
    }
  });

  // ===== Scan Process =====
  dom.btnScan.addEventListener('click', startScan);
  dom.btnAbort.addEventListener('click', abortScan);

  async function startScan() {
    if (!state.selectedPath) return;

    state.scanMode = 'mods';
    state.scanning = true;
    dom.scanTitle.textContent = 'Scanning Mods';
    showScreen('scanning');
    resetScanStats();

    // Set up progress listener
    window.electronAPI.onScanProgress((data) => {
      updateScanProgress(data);
    });

    window.electronAPI.onModScanned((data) => {
      updateScanLiveStats(data);
    });

    window.electronAPI.onScanComplete((data) => {
      state.scanResults = data.results;
      state.scanSummary = data.summary;
      state.scanning = false;
      showResults();
    });

    // Start the scan
    const result = await window.electronAPI.startScan(state.selectedPath);

    if (!result.success) {
      alert(`Scan failed: ${result.error}`);
      showScreen('home');
      state.scanning = false;
    }
  }

  function abortScan() {
    if (state.scanMode === 'config') {
      window.electronAPI.abortConfigScan();
    } else {
      window.electronAPI.abortScan();
    }
    // Detach listeners so a late "complete" event can't hijack navigation
    ['scan-progress', 'mod-scanned', 'scan-complete',
     'config-scan-progress', 'config-scan-complete'].forEach((ch) => {
      window.electronAPI.removeAllListeners?.(ch);
    });
    state.scanning = false;
    showScreen('home');
  }

  // ===== %APPDATA% Cheat Config Scan =====
  dom.btnConfigScan.addEventListener('click', startConfigScan);

  dom.btnConfigBack.addEventListener('click', () => {
    state.configResults = null;
    state.configSummary = null;
    showScreen('home');
  });

  dom.configSearch.addEventListener('input', (e) => {
    state.configQuery = e.target.value.toLowerCase();
    renderConfigGrid();
  });

  async function startConfigScan() {
    state.scanMode = 'config';
    state.scanning = true;
    dom.scanTitle.textContent = 'Scanning %APPDATA%';
    showScreen('scanning');
    resetScanStats();

    window.electronAPI.onConfigScanProgress((data) => {
      updateConfigScanProgress(data);
    });

    window.electronAPI.onConfigScanComplete((data) => {
      state.configResults = data.results;
      state.configSummary = data.summary;
      state.scanning = false;
      showConfigResults();
    });

    const result = await window.electronAPI.startAppDataScan();

    if (!result.success) {
      alert(`Config scan failed: ${result.error}`);
      showScreen('home');
      state.scanning = false;
    } else if (result.aborted) {
      state.scanning = false;
    }
  }

  function updateConfigScanProgress(data) {
    dom.scanPhase.textContent = data.phase || 'Scanning...';
    dom.scanProgressFill.style.width = `${data.percent || 0}%`;
    dom.scanCounter.textContent = `${data.current || 0} / ${data.total || 0}`;
    dom.scanPercent.textContent = `${data.percent || 0}%`;
    dom.scanCurrentFile.textContent = data.currentMod || '-';

    const current = data.current || 0;
    const found = data.found || 0;
    dom.statTotal.textContent = current;
    dom.statSafe.textContent = Math.max(0, current - found);
    dom.statWarning.textContent = data.warningCount || 0;
    dom.statCritical.textContent = data.criticalCount || 0;
  }

  function showConfigResults() {
    const s = state.configSummary;
    if (!s) return;

    dom.configResultsTime.textContent = new Date(s.timestamp).toLocaleString();
    dom.cfgSumScanned.textContent = s.analyzed;
    dom.cfgSumFound.textContent = s.found;
    dom.cfgSumCritical.textContent = s.critical;
    dom.cfgSumWarning.textContent = s.warning;

    // Show which launcher folders were scanned (as chips)
    const esc = (str) => String(str).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const launchers = s.launchers || [];
    if (launchers.length > 0) {
      dom.configLaunchers.style.display = 'block';
      dom.configLaunchers.style.color = '';
      dom.configLaunchers.className = 'launchers-bar';
      dom.configLaunchers.innerHTML =
        `<span class="launchers-label">🎮 Launchers scanned (${launchers.length})</span>` +
        launchers.map(l => `<span class="launcher-chip">${esc(l)}</span>`).join('');
    } else {
      dom.configLaunchers.style.display = 'block';
      dom.configLaunchers.style.color = 'var(--warning-color)';
      dom.configLaunchers.className = '';
      dom.configLaunchers.textContent =
        '⚠️ No Minecraft launcher folders were detected inside %APPDATA%';
    }

    // Clean-file counter (scanned files that were NOT flagged)
    const analyzedCount = s.analyzed || 0;
    const foundCount = s.found || 0;
    if (dom.cfgSumClean) {
      dom.cfgSumClean.textContent = Math.max(0, analyzedCount - foundCount);
    }

    dom.configSearch.value = '';
    state.configQuery = '';

    renderConfigGrid();
    showScreen('configResults');
  }

  function renderConfigGrid() {
    let results = [...(state.configResults || [])];

    if (state.configQuery) {
      results = results.filter(r =>
        (`${r.name} ${r.path || ''}`).toLowerCase().includes(state.configQuery)
      );
    }

    const severityOrder = { critical: 0, suspicious: 1, warning: 2, error: 3, safe: 4 };
    results.sort((a, b) => (severityOrder[a.threatLevel] ?? 5) - (severityOrder[b.threatLevel] ?? 5));

    const noLaunchers = !(state.configSummary?.launchers?.length);
    const emptyHtml = noLaunchers
      ? `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <div class="empty-state-icon">🎮</div>
        <div class="empty-state-title">No Minecraft launchers found</div>
        <div class="empty-state-desc">No launcher folders (.minecraft, Prism, MultiMC, CurseForge, ...) exist inside %APPDATA%</div>
      </div>
    `
      : `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <div class="empty-state-icon">🎉</div>
        <div class="empty-state-title">No cheat configs found</div>
        <div class="empty-state-desc">No config file inside your Minecraft launchers matched a cheat configuration</div>
      </div>
    `;

    window.renderModCards(results, dom.configGrid, emptyHtml);
  }

  function loadAppDataPath() {
    window.electronAPI?.getAppDataPath?.().then((info) => {
      if (info && info.exists) {
        dom.configPathText.textContent = info.path;
        dom.configPathDisplay.style.display = 'flex';
      }
    }).catch(() => {});
  }

  function resetScanStats() {
    dom.scanPhase.textContent = 'Initializing...';
    dom.scanProgressFill.style.width = '0%';
    dom.scanCounter.textContent = '0 / 0';
    dom.scanPercent.textContent = '0%';
    dom.scanCurrentFile.textContent = '-';
    dom.statTotal.textContent = '0';
    dom.statSafe.textContent = '0';
    dom.statWarning.textContent = '0';
    dom.statCritical.textContent = '0';
  }

  function updateScanProgress(data) {
    dom.scanPhase.textContent = data.phase || 'Scanning...';
    dom.scanProgressFill.style.width = `${data.percent || 0}%`;
    dom.scanCounter.textContent = `${data.current || 0} / ${data.total || 0}`;
    dom.scanPercent.textContent = `${data.percent || 0}%`;
    dom.scanCurrentFile.textContent = data.currentMod || '-';
    dom.statTotal.textContent = data.current || 0;
  }

  let scanStats = { safe: 0, warning: 0, critical: 0 };

  function updateScanLiveStats(data) {
    if (!data.analysis) return;
    const level = data.analysis.threatLevel;
    if (level === 'safe' || data.analysis.verified) {
      scanStats.safe++;
    } else if (level === 'critical') {
      scanStats.critical++;
    } else {
      scanStats.warning++;
    }
    dom.statSafe.textContent = scanStats.safe;
    dom.statWarning.textContent = scanStats.warning;
    dom.statCritical.textContent = scanStats.critical;
  }

  // ===== Results Display =====
  function showResults() {
    scanStats = { safe: 0, warning: 0, critical: 0 };

    if (!state.scanResults || !state.scanSummary) return;

    const s = state.scanSummary;
    dom.resultsTime.textContent = new Date(s.timestamp).toLocaleString();
    dom.sumTotal.textContent = s.total;
    dom.sumSafe.textContent = s.safe;
    dom.sumWarning.textContent = s.suspicious;
    dom.sumCritical.textContent = s.critical;
    dom.sumObfuscated.textContent = s.obfuscated;

    // Update filter counts
    dom.filterAll.textContent = s.total;
    dom.filterCritical.textContent = s.critical;
    dom.filterSuspicious.textContent = s.suspicious;
    dom.filterWarning.textContent = state.scanResults.filter(r =>
      r.threatLevel === 'warning'
    ).length;
    dom.filterSafe.textContent = s.safe;
    dom.filterObfuscated.textContent = s.obfuscated;

    // Render mod cards
    renderModCards(state.scanResults);

    showScreen('results');
  }

  // ===== Filter Tabs =====
  document.querySelectorAll('.filter-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.currentFilter = tab.dataset.filter;
      filterAndRenderMods();
    });
  });

  // ===== Search =====
  dom.resultsSearch.addEventListener('input', (e) => {
    state.searchQuery = e.target.value.toLowerCase();
    filterAndRenderMods();
  });

  function filterAndRenderMods() {
    if (!state.scanResults) return;
    let filtered = [...state.scanResults];

    // Apply filter
    switch (state.currentFilter) {
      case 'critical':
        filtered = filtered.filter(r => r.threatLevel === 'critical');
        break;
      case 'suspicious':
        filtered = filtered.filter(r => r.threatLevel === 'suspicious');
        break;
      case 'warning':
        filtered = filtered.filter(r => r.threatLevel === 'warning');
        break;
      case 'safe':
        filtered = filtered.filter(r => r.threatLevel === 'safe' || r.verified);
        break;
      case 'obfuscated':
        filtered = filtered.filter(r => r.obfuscationAnalysis?.isObfuscated);
        break;
      default:
        break;
    }

    // Apply search
    if (state.searchQuery) {
      filtered = filtered.filter(r =>
        r.name.toLowerCase().includes(state.searchQuery) ||
        (r.modId && r.modId.toLowerCase().includes(state.searchQuery))
      );
    }

    // Sort: critical first, then suspicious, then warning, then safe
    const severityOrder = { critical: 0, suspicious: 1, warning: 2, error: 3, safe: 4 };
    filtered.sort((a, b) => (severityOrder[a.threatLevel] || 5) - (severityOrder[b.threatLevel] || 5));

    renderModCards(filtered);
  }

  // ===== Back Button =====
  dom.btnBack.addEventListener('click', () => {
    state.scanResults = null;
    state.scanSummary = null;
    showScreen('home');
  });

  // ===== Modal =====
  dom.modalClose.addEventListener('click', closeModal);
  dom.modalOverlay.addEventListener('click', (e) => {
    if (e.target === dom.modalOverlay) closeModal();
  });

  function closeModal() {
    dom.modalOverlay.style.display = 'none';
  }

  // Export state and dom to global scope for other modules
  window.appState = state;
  window.appDom = dom;
  window.showModal = function(analysis) {
    if (typeof window.renderDetail === 'function') {
      window.renderDetail(analysis);
    }
    dom.modalOverlay.style.display = 'flex';
  };

  // ===== Initialize =====
  loadAppDataPath();
  showScreen('home');

})();
