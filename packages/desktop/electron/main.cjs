const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { autoUpdater } = require('electron-updater');
const {
  analyzeBinaryTarget,
  disassembleFunctionAtAddress,
  detectGhidraInstallation,
} = require('./disassembler.cjs');

let mainWindow = null;

// Configure updater
autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;

function getAegisConfigDir() {
  return path.join(app.getPath('appData'), 'AegisRE');
}

function readAegisConfig() {
  try {
    const configFile = path.join(getAegisConfigDir(), 'config.json');
    if (fs.existsSync(configFile)) {
      return JSON.parse(fs.readFileSync(configFile, 'utf8')) || {};
    }
  } catch (err) {
    console.error('Error reading AegisRE config file:', err);
  }
  return {};
}

function writeAegisConfig(patch) {
  try {
    const dir = getAegisConfigDir();
    fs.mkdirSync(dir, { recursive: true });
    const configFile = path.join(dir, 'config.json');
    const existing = readAegisConfig();
    const merged = { ...existing, ...patch };
    fs.writeFileSync(configFile, JSON.stringify(merged, null, 2), 'utf8');
    return merged;
  } catch (err) {
    console.error('Error writing AegisRE config file:', err);
    return {};
  }
}

// Helper: Resolve GitHub token from environment or %APPDATA%\AegisRE\config.json
function resolveGithubToken() {
  if (process.env.AEGIS_GITHUB_TOKEN) {
    return process.env.AEGIS_GITHUB_TOKEN.trim();
  }
  if (process.env.GH_TOKEN) {
    return process.env.GH_TOKEN.trim();
  }
  if (process.env.GITHUB_TOKEN) {
    return process.env.GITHUB_TOKEN.trim();
  }
  const cfg = readAegisConfig();
  if (cfg.githubToken && typeof cfg.githubToken === 'string') {
    return cfg.githubToken.trim();
  }
  return '';
}

function createWindow() {
  const cfg = readAegisConfig();
  const isLight = cfg.theme === 'light';

  mainWindow = new BrowserWindow({
    width: 1520,
    height: 940,
    minWidth: 1080,
    minHeight: 720,
    title: 'AegisRE Studio',
    backgroundColor: isLight ? '#f8fafc' : '#020617',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: isLight ? '#ffffff' : '#0f172a',
      symbolColor: isLight ? '#334155' : '#94a3b8',
      height: 46,
    },
  });

  const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
  if (isDev && process.env.VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Allow renderer to dynamically update Windows titleBarOverlay when toggling Light/Dark mode
ipcMain.handle('theme:set', (event, themeMode) => {
  const isLight = themeMode === 'light';
  writeAegisConfig({ theme: isLight ? 'light' : 'dark' });
  if (mainWindow && !mainWindow.isDestroyed() && typeof mainWindow.setTitleBarOverlay === 'function') {
    try {
      mainWindow.setTitleBarOverlay({
        color: isLight ? '#ffffff' : '#0f172a',
        symbolColor: isLight ? '#334155' : '#94a3b8',
        height: 46,
      });
    } catch (_) {}
  }
  return { success: true, theme: isLight ? 'light' : 'dark' };
});

ipcMain.handle('theme:get', () => {
  const cfg = readAegisConfig();
  return cfg.theme === 'light' ? 'light' : 'dark';
});

// Updater event forwarders
function sendUpdateStatus(status, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('updater:status', { status, data });
  }
}

autoUpdater.on('checking-for-update', () => sendUpdateStatus('checking', null));
autoUpdater.on('update-available', (info) => sendUpdateStatus('available', info));
autoUpdater.on('update-not-available', (info) => sendUpdateStatus('not-available', info));
autoUpdater.on('error', (err) =>
  sendUpdateStatus('error', err == null ? 'unknown' : (err.stack || err).toString())
);
autoUpdater.on('download-progress', (progressObj) => sendUpdateStatus('downloading', progressObj));
autoUpdater.on('update-downloaded', (info) => sendUpdateStatus('downloaded', info));

ipcMain.handle('updater:check', async (event, explicitToken) => {
  try {
    const token = explicitToken || resolveGithubToken();
    if (token) {
      autoUpdater.requestHeaders = {
        Authorization: `token ${token}`,
      };
    }
    const result = await autoUpdater.checkForUpdates();
    return { success: true, updateInfo: result?.updateInfo };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('updater:hasToken', () => Boolean(resolveGithubToken()));

ipcMain.handle('updater:download', async () => {
  try {
    await autoUpdater.downloadUpdate();
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('updater:install', () => {
  autoUpdater.quitAndInstall();
});

ipcMain.handle('app:version', () => app.getVersion());

ipcMain.handle('dialog:openFile', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select an App or Binary to Reverse Engineer in AegisRE Studio',
    properties: ['openFile'],
    filters: [
      {
        name: 'All Supported Binaries & Packages',
        extensions: ['exe', 'dll', 'sys', 'elf', 'so', 'dylib', 'wasm', 'asar', 'apk', 'zip', 'msi'],
      },
      { name: 'Windows Executables & Libraries (.exe, .dll, .sys)', extensions: ['exe', 'dll', 'sys'] },
      { name: 'Web, Electron & Mobile Packages (.asar, .apk, .zip, .wasm)', extensions: ['wasm', 'asar', 'apk', 'zip'] },
      { name: 'All Files (*.*)', extensions: ['*'] },
    ],
  });

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  const filePath = result.filePaths[0];
  const stats = fs.statSync(filePath);
  return {
    path: filePath,
    name: path.basename(filePath),
    size: stats.size,
    modified: stats.mtimeMs,
  };
});

ipcMain.handle('aegis:getLatestTarget', async () => {
  try {
    const bridgeFile = path.join(getAegisConfigDir(), 'latest-target.json');
    if (fs.existsSync(bridgeFile)) {
      const data = JSON.parse(fs.readFileSync(bridgeFile, 'utf8'));
      if (data && data.success && data.target) {
        return data;
      }
    }
  } catch (_) {}
  return null;
});

ipcMain.handle('aegis:analyzeTarget', async (event, filePath) => {
  try {
    if (!filePath || !fs.existsSync(filePath)) {
      return {
        success: false,
        error: `File not found: ${filePath || '(empty path)'}`,
      };
    }
    const result = analyzeBinaryTarget(filePath);
    try {
      const bridgeDir = getAegisConfigDir();
      fs.mkdirSync(bridgeDir, { recursive: true });
      const bridgeFile = path.join(bridgeDir, 'latest-target.json');
      fs.writeFileSync(
        bridgeFile,
        JSON.stringify({ inspectedAt: new Date().toISOString(), ...result }, null, 2),
        'utf8'
      );
      result.antigravityBridgePath = bridgeFile;
    } catch (bridgeErr) {
      console.error('Failed writing Antigravity bridge file:', bridgeErr);
    }
    return result;
  } catch (err) {
    return {
      success: false,
      error: err.message || String(err),
    };
  }
});

ipcMain.handle('aegis:disassembleAt', async (event, { filePath, address, size }) => {
  try {
    if (!filePath || !fs.existsSync(filePath)) {
      return { success: false, error: 'Target file not found on disk.' };
    }
    return disassembleFunctionAtAddress(filePath, address, size || 512);
  } catch (err) {
    return { success: false, error: err.message || String(err) };
  }
});

ipcMain.handle('aegis:ghidraStatus', async () => {
  const cfg = readAegisConfig();
  return detectGhidraInstallation(cfg.ghidraPath);
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
