const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  windowMinimize: () => ipcRenderer.send('window-minimize'),
  windowMaximize: () => ipcRenderer.send('window-maximize'),
  windowClose: () => ipcRenderer.send('window-close'),

  // Directory selection
  selectDirectory: () => ipcRenderer.invoke('select-directory'),
  getDefaultModsPath: () => ipcRenderer.invoke('get-default-mods-path'),

  // Scan controls
  startScan: (dirPath) => ipcRenderer.invoke('start-scan', dirPath),
  abortScan: () => ipcRenderer.invoke('abort-scan'),

  // %APPDATA% cheat config scan
  getAppDataPath: () => ipcRenderer.invoke('get-appdata-path'),
  startAppDataScan: () => ipcRenderer.invoke('start-appdata-scan'),
  abortConfigScan: () => ipcRenderer.invoke('abort-config-scan'),

  // Event listeners
  onScanProgress: (callback) => {
    ipcRenderer.removeAllListeners('scan-progress');
    ipcRenderer.on('scan-progress', (event, data) => callback(data));
  },
  onModScanned: (callback) => {
    ipcRenderer.removeAllListeners('mod-scanned');
    ipcRenderer.on('mod-scanned', (event, data) => callback(data));
  },
  onScanComplete: (callback) => {
    ipcRenderer.removeAllListeners('scan-complete');
    ipcRenderer.on('scan-complete', (event, data) => callback(data));
  },
  onConfigScanProgress: (callback) => {
    ipcRenderer.removeAllListeners('config-scan-progress');
    ipcRenderer.on('config-scan-progress', (event, data) => callback(data));
  },
  onConfigScanComplete: (callback) => {
    ipcRenderer.removeAllListeners('config-scan-complete');
    ipcRenderer.on('config-scan-complete', (event, data) => callback(data));
  },
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});
