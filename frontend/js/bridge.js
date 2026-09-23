/**
 * WonderAnalyzer — Tauri bridge
 *
 * Re-implements the exact `window.electronAPI` surface that the Electron
 * preload exposed, over Tauri invoke/event. Under Electron this file is a
 * no-op (the preload already provided electronAPI).
 */
(function () {
  'use strict';

  if (window.electronAPI || !window.__TAURI__) return;

  const invoke = window.__TAURI__.core.invoke;
  const listeners = {};        // channel -> [unlistenFn]
  const subscribeGen = {};      // channel -> generation counter
  let dragWired = false;

  function subscribe(channel, callback) {
    const gen = (subscribeGen[channel] = (subscribeGen[channel] || 0) + 1);

    // Drop listeners from the previous subscription (parity with the
    // Electron preload's removeAllListeners + on-pair).
    (listeners[channel] || []).forEach((un) => { try { un(); } catch (e) {} });
    listeners[channel] = [];

    window.__TAURI__.event
      .listen(channel, (event) => {
        // Ignore callbacks from a stale subscription (re-subscribed while
        // this listen was still resolving) — prevents ghost handlers that
        // double-render results after several scans.
        if (subscribeGen[channel] !== gen) return;
        callback(event.payload);
      })
      .then((unlisten) => {
        if (subscribeGen[channel] !== gen) {
          // This subscription was already replaced/removed: don't leak it.
          try { unlisten(); } catch (e) {}
          return;
        }
        (listeners[channel] = listeners[channel] || []).push(unlisten);
      });
  }

  function removeAllListeners(channel) {
    subscribeGen[channel] = (subscribeGen[channel] || 0) + 1;
    (listeners[channel] || []).forEach((un) => { try { un(); } catch (e) {} });
    listeners[channel] = [];
  }

  function wireDragDrop() {
    if (dragWired) return;
    dragWired = true;
    try {
      window.__TAURI__.window
        .getCurrentWindow()
        .onDragDropEvent((event) => {
          if (event.payload.type === 'drop' && event.payload.paths && event.payload.paths[0]) {
            if (typeof window.__setSelectedDirectory === 'function') {
              window.__setSelectedDirectory(event.payload.paths[0]);
            }
          }
        });
    } catch (e) { /* drag-drop optional */ }
  }

  window.electronAPI = {
    // Window controls
    windowMinimize: () => invoke('window_minimize'),
    windowMaximize: () => invoke('window_maximize'),
    windowClose: () => invoke('window_close'),

    // Directory selection
    selectDirectory: () => invoke('select_directory'),
    getDefaultModsPath: () => invoke('get_default_mods_path'),

    // Scan controls
    startScan: (dirPath) => invoke('start_scan', { dirpath: dirPath }),
    abortScan: () => invoke('abort_scan'),

    // %APPDATA% cheat config scan
    getAppDataPath: () => invoke('get_appdata_path'),
    startAppDataScan: () => invoke('start_appdata_scan'),
    abortConfigScan: () => invoke('abort_config_scan'),

    // Event listeners (parity with the Electron preload)
    onScanProgress: (callback) => subscribe('scan-progress', callback),
    onModScanned: (callback) => subscribe('mod-scanned', callback),
    onScanComplete: (callback) => subscribe('scan-complete', callback),
    onConfigScanProgress: (callback) => subscribe('config-scan-progress', callback),
    onConfigScanComplete: (callback) => subscribe('config-scan-complete', callback),
    removeAllListeners,
  };

  wireDragDrop();
})();
