/**
 * WonderAnalyzer - Main Electron Process
 */

const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { ModScanner } = require('./backend/scanner');
const { ConfigScanner } = require('./backend/configScanner');

let mainWindow = null;
let scanner = null;
let configScanner = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    frame: false,
    titleBarStyle: 'hidden',
    backgroundColor: '#0a0a0f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
    icon: path.join(__dirname, 'assets', 'icons', 'icon.png'),
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'frontend', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Window control handlers
ipcMain.on('window-minimize', () => mainWindow?.minimize());
ipcMain.on('window-maximize', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});
ipcMain.on('window-close', () => mainWindow?.close());

// Directory selection
ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Minecraft Mods Folder',
    defaultPath: path.join(
      process.env.APPDATA || process.env.HOME,
      '.minecraft', 'mods'
    )
  });

  if (result.canceled) return null;
  return result.filePaths[0];
});

// Get default mods path
ipcMain.handle('get-default-mods-path', () => {
  const defaultPath = path.join(
    process.env.APPDATA || process.env.HOME,
    '.minecraft', 'mods'
  );
  return {
    path: defaultPath,
    exists: fs.existsSync(defaultPath)
  };
});

// Start scan
ipcMain.handle('start-scan', async (event, dirPath) => {
  if (scanner) {
    scanner.abort();
  }

  scanner = new ModScanner(mainWindow.webContents);

  try {
    const results = await scanner.scanDirectory(dirPath);
    return { success: true, results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Abort scan
ipcMain.handle('abort-scan', () => {
  if (scanner) {
    scanner.abort();
    scanner = null;
  }
  return true;
});

// ===== %APPDATA% cheat config scan =====

// Get the Roaming AppData path
ipcMain.handle('get-appdata-path', () => {
  const appData = process.env.APPDATA;
  if (!appData) return null;
  return {
    path: appData,
    exists: fs.existsSync(appData)
  };
});

// Start automatic %APPDATA% cheat config scan
ipcMain.handle('start-appdata-scan', async () => {
  if (configScanner) {
    configScanner.abort();
  }

  const appData = process.env.APPDATA;
  if (!appData || !fs.existsSync(appData)) {
    return { success: false, error: '%APPDATA% folder not found on this system' };
  }

  configScanner = new ConfigScanner(mainWindow.webContents);

  try {
    const result = await configScanner.scan(appData);
    return { success: true, ...result };
  } catch (err) {
    return { success: false, error: err.message };
  } finally {
    configScanner = null;
  }
});

// Abort %APPDATA% config scan
ipcMain.handle('abort-config-scan', () => {
  if (configScanner) {
    configScanner.abort();
    configScanner = null;
  }
  return true;
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
