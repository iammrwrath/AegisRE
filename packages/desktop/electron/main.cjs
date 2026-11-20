const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const {
  analyzeBinaryTarget,
  disassembleFunctionAtAddress,
  detectGhidraInstallation,
  generateAntigravityReport,
} = require('./disassembler.cjs');

let mainWindow = null;

const GITHUB_OWNER = 'iammrwrath';
const GITHUB_REPO = 'AegisRE';
let latestReleaseInfo = null;

function readCurrentAppVersion() {
  try {
    const pkgPath = path.resolve(__dirname, '../package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg && typeof pkg.version === 'string' && pkg.version.trim()) {
        return pkg.version.trim();
      }
    }
  } catch (err) {
    console.error('Error reading package.json version:', err);
  }
  return app.getVersion();
}

function compareVersions(a, b) {
  const parse = (v) => {
    const clean = String(v || '').trim().replace(/^v/i, '');
    const [core, pre = ''] = clean.split('-', 2);
    const parts = core.split('.').map((n) => {
      const parsed = parseInt(n, 10);
      return Number.isNaN(parsed) ? 0 : parsed;
    });
    return { parts, pre };
  };
  const va = parse(a);
  const vb = parse(b);
  const len = Math.max(va.parts.length, vb.parts.length, 3);
  for (let i = 0; i < len; i++) {
    const na = va.parts[i] || 0;
    const nb = vb.parts[i] || 0;
    if (na !== nb) return na > nb ? 1 : -1;
  }
  if (va.pre && !vb.pre) return -1;
  if (!va.pre && vb.pre) return 1;
  if (va.pre && vb.pre && va.pre !== vb.pre) return va.pre > vb.pre ? 1 : -1;
  return 0;
}

function httpsGetBuffer(urlOrPath, token, acceptHeader, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const isAbsolute = /^https?:\/\//i.test(urlOrPath);
    const targetUrl = isAbsolute ? new URL(urlOrPath) : new URL(`https://api.github.com${urlOrPath}`);
    const headers = {
      'User-Agent': 'AegisRE-Studio',
      Accept: acceptHeader || 'application/vnd.github+json',
    };
    if (token && targetUrl.hostname === 'api.github.com') {
      headers.Authorization = `Bearer ${token}`;
    }

    const req = https.get(targetUrl, { headers }, (res) => {
      const statusCode = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(statusCode) && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) {
          reject(new Error(`Too many redirects while fetching ${targetUrl.pathname}`));
          return;
        }
        const nextUrl = new URL(res.headers.location, targetUrl).toString();
        httpsGetBuffer(nextUrl, token, acceptHeader, redirectsLeft - 1).then(resolve, reject);
        return;
      }

      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        if (statusCode >= 200 && statusCode < 300) {
          resolve(body);
          return;
        }
        let detail = `GitHub API returned HTTP ${statusCode}`;
        try {
          const parsed = JSON.parse(body.toString('utf8'));
          if (parsed && parsed.message) {
            detail = `${detail}: ${parsed.message}`;
          }
        } catch (_) {}
        const err = new Error(detail);
        err.statusCode = statusCode;
        reject(err);
      });
    });

    req.setTimeout(15000, () => {
      req.destroy(new Error('Request to GitHub timed out'));
    });
    req.on('error', reject);
  });
}

async function githubApiJson(apiPath, token) {
  const buf = await httpsGetBuffer(apiPath, token, 'application/vnd.github+json');
  return JSON.parse(buf.toString('utf8'));
}

async function githubDownloadFile(apiPath, token) {
  return httpsGetBuffer(apiPath, token, 'application/vnd.github.raw+json');
}

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

ipcMain.handle('updater:check', async (event, explicitToken) => {
  try {
    const trimmedExplicit = typeof explicitToken === 'string' ? explicitToken.trim() : '';
    if (trimmedExplicit) {
      writeAegisConfig({ githubToken: trimmedExplicit });
    }
    const token = trimmedExplicit || resolveGithubToken();
    sendUpdateStatus('checking', null);

    let release = null;
    try {
      release = await githubApiJson(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases/latest`, token);
    } catch (err) {
      if (err && err.statusCode === 404) {
        const list = await githubApiJson(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases?per_page=5`, token);
        if (Array.isArray(list) && list.length > 0) {
          release = list.find((r) => r && !r.draft) || list[0];
        }
      } else {
        throw err;
      }
    }

    const currentVersion = readCurrentAppVersion();
    if (!release || !release.tag_name) {
      latestReleaseInfo = null;
      const info = { version: currentVersion, latestVersion: currentVersion };
      sendUpdateStatus('not-available', info);
      return { success: true, status: 'not-available', updateInfo: info };
    }

    const latestVersion = String(release.tag_name || '').replace(/^v/i, '');
    const updateInfo = {
      version: latestVersion,
      currentVersion,
      tagName: release.tag_name,
      name: release.name || release.tag_name,
      releaseDate: release.published_at || release.created_at || null,
      releaseNotes: release.body || '',
      htmlUrl: release.html_url || '',
    };
    latestReleaseInfo = updateInfo;

    if (latestVersion && compareVersions(latestVersion, currentVersion) > 0) {
      sendUpdateStatus('available', updateInfo);
      return { success: true, status: 'available', updateInfo };
    }

    const notAvailableInfo = {
      ...updateInfo,
      version: currentVersion,
      latestVersion: latestVersion || currentVersion,
    };
    sendUpdateStatus('not-available', notAvailableInfo);
    return { success: true, status: 'not-available', updateInfo: notAvailableInfo };
  } catch (err) {
    const msg = (err && err.message) || 'Failed to check GitHub releases';
    sendUpdateStatus('error', msg);
    return { success: false, error: msg };
  }
});

ipcMain.handle('updater:hasToken', () => Boolean(resolveGithubToken()));

ipcMain.handle('updater:download', async () => {
  try {
    const token = resolveGithubToken();
    const targetVersion = (latestReleaseInfo && latestReleaseInfo.version) || readCurrentAppVersion();
    sendUpdateStatus('downloading', { percent: 10 });

    const appRoot = path.resolve(__dirname, '..');
    const refQuery =
      latestReleaseInfo && latestReleaseInfo.tagName
        ? `?ref=${encodeURIComponent(latestReleaseInfo.tagName)}`
        : '';

    const filesToSync = [
      { repoPath: 'packages/desktop/electron/ui.html', localRel: 'dist/index.html', percent: 30 },
      { repoPath: 'packages/desktop/electron/main.cjs', localRel: 'dist-electron/main.cjs', percent: 55 },
      { repoPath: 'packages/desktop/electron/preload.cjs', localRel: 'dist-electron/preload.cjs', percent: 80 },
      { repoPath: 'packages/desktop/electron/disassembler.cjs', localRel: 'dist-electron/disassembler.cjs', percent: 95 },
    ];

    for (const file of filesToSync) {
      try {
        const buf = await githubDownloadFile(
          `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${file.repoPath}${refQuery}`,
          token
        );
        const destPath = path.join(appRoot, file.localRel);
        fs.mkdirSync(path.dirname(destPath), { recursive: true });
        fs.writeFileSync(destPath, buf);
      } catch (fileErr) {
        if (!fileErr || fileErr.statusCode !== 404) {
          throw fileErr;
        }
      }
      sendUpdateStatus('downloading', { percent: file.percent });
    }

    const pkgPath = path.join(appRoot, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      pkg.version = targetVersion;
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
    }

    sendUpdateStatus('downloaded', { version: targetVersion });
    return { success: true, version: targetVersion };
  } catch (err) {
    const msg = (err && err.message) || 'Failed to download update';
    sendUpdateStatus('error', msg);
    return { success: false, error: msg };
  }
});

ipcMain.handle('updater:install', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.reloadIgnoringCache();
  }
  app.relaunch();
  app.exit(0);
});

ipcMain.handle('app:version', () => readCurrentAppVersion());

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

function writeAntigravityBridgeFiles(analysisResult, options = {}) {
  const bridgeDir = getAegisConfigDir();
  const reportsDir = path.join(bridgeDir, 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  const safeName = String(analysisResult?.target?.name || 'target').replace(/[^a-zA-Z0-9._-]+/g, '_');
  const bridgeFile = path.join(bridgeDir, 'latest-target.json');
  const latestReportFile = path.join(bridgeDir, 'latest-report.md');
  const namedReportFile = path.join(reportsDir, `${safeName}-antigravity-report.md`);

  analysisResult.antigravityBridgePath = bridgeFile;
  analysisResult.antigravityReportPath = latestReportFile;
  analysisResult.savedReportPath = namedReportFile;

  const reportMarkdown = generateAntigravityReport(analysisResult, options);
  fs.writeFileSync(latestReportFile, reportMarkdown, 'utf8');
  fs.writeFileSync(namedReportFile, reportMarkdown, 'utf8');

  const { reportMarkdown: _omitReport, ...jsonPayload } = analysisResult;
  fs.writeFileSync(
    bridgeFile,
    JSON.stringify({ inspectedAt: analysisResult.inspectedAt || new Date().toISOString(), ...jsonPayload }, null, 2),
    'utf8'
  );

  analysisResult.reportMarkdown = reportMarkdown;
  return {
    reportMarkdown,
    bridgeFile,
    latestReportFile,
    namedReportFile,
  };
}

ipcMain.handle('aegis:getLatestTarget', async () => {
  try {
    const bridgeFile = path.join(getAegisConfigDir(), 'latest-target.json');
    if (fs.existsSync(bridgeFile)) {
      const data = JSON.parse(fs.readFileSync(bridgeFile, 'utf8'));
      if (data && data.success && data.target) {
        if (!data.antigravityReportPath) {
          data.antigravityReportPath = path.join(getAegisConfigDir(), 'latest-report.md');
        }
        if (!data.savedReportPath) {
          const safeName = String(data.target.name || 'target').replace(/[^a-zA-Z0-9._-]+/g, '_');
          data.savedReportPath = path.join(getAegisConfigDir(), 'reports', `${safeName}-antigravity-report.md`);
        }
        if (!data.reportMarkdown) {
          data.reportMarkdown = generateAntigravityReport(data);
        }
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
      writeAntigravityBridgeFiles(result);
    } catch (bridgeErr) {
      console.error('Failed writing Antigravity bridge files:', bridgeErr);
    }
    return result;
  } catch (err) {
    return {
      success: false,
      error: err.message || String(err),
    };
  }
});

ipcMain.handle('aegis:generateReport', async (event, { analysisData, options } = {}) => {
  try {
    if (!analysisData || !analysisData.target) {
      return { success: false, error: 'No analyzed target provided to generate report.' };
    }
    const payload = { ...analysisData };
    const written = writeAntigravityBridgeFiles(payload, options || {});
    return {
      success: true,
      reportMarkdown: written.reportMarkdown,
      reportPath: written.latestReportFile,
      savedReportPath: written.namedReportFile,
    };
  } catch (err) {
    return { success: false, error: err.message || String(err) };
  }
});

ipcMain.handle('aegis:saveReport', async (event, { reportMarkdown, analysisData, defaultFileName, format } = {}) => {
  try {
    const isJson = format === 'json';
    const baseTarget = String(analysisData?.target?.name || 'target').replace(/[^a-zA-Z0-9._-]+/g, '_');
    const suggestedName = defaultFileName || `${baseTarget}-antigravity-report.${isJson ? 'json' : 'md'}`;

    const filters = isJson
      ? [
          { name: 'JSON Analysis Bundle (.json)', extensions: ['json'] },
          { name: 'Markdown Report (.md)', extensions: ['md'] },
          { name: 'All Files (*.*)', extensions: ['*'] },
        ]
      : [
          { name: 'Markdown Report (.md)', extensions: ['md'] },
          { name: 'Plain Text Report (.txt)', extensions: ['txt'] },
          { name: 'JSON Analysis Bundle (.json)', extensions: ['json'] },
        ];

    const saveResult = await dialog.showSaveDialog(mainWindow, {
      title: 'Save Antigravity Reverse-Engineering Report',
      defaultPath: path.join(app.getPath('documents'), suggestedName),
      filters,
    });

    if (saveResult.canceled || !saveResult.filePath) {
      return { success: false, canceled: true };
    }

    const chosenExt = path.extname(saveResult.filePath).toLowerCase();
    if (isJson || chosenExt === '.json') {
      fs.writeFileSync(saveResult.filePath, JSON.stringify(analysisData || {}, null, 2), 'utf8');
    } else {
      const content = reportMarkdown || generateAntigravityReport(analysisData || {});
      fs.writeFileSync(saveResult.filePath, content, 'utf8');
    }

    return { success: true, filePath: saveResult.filePath };
  } catch (err) {
    return { success: false, error: err.message || String(err) };
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
