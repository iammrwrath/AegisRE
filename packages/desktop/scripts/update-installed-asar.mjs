import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const resourcesDir = 'C:\\Users\\icell\\AppData\\Local\\Programs\\AegisRE Studio\\resources';
const appDir = path.join(resourcesDir, 'app');
const desktopDir = path.resolve(__dirname, '..');

function copyRecursiveSync(src, dest) {
  const exists = fs.existsSync(src);
  const stats = exists && fs.statSync(src);
  const isDirectory = exists && stats.isDirectory();
  if (isDirectory) {
    fs.mkdirSync(dest, { recursive: true });
    for (const childItemName of fs.readdirSync(src)) {
      copyRecursiveSync(path.join(src, childItemName), path.join(dest, childItemName));
    }
  } else {
    fs.copyFileSync(src, dest);
  }
}

// Create resources/app/ with dist, dist-electron, package.json, and required node_modules
fs.mkdirSync(path.join(appDir, 'dist'), { recursive: true });
fs.mkdirSync(path.join(appDir, 'dist-electron'), { recursive: true });

copyRecursiveSync(path.join(desktopDir, 'dist'), path.join(appDir, 'dist'));
copyRecursiveSync(path.join(desktopDir, 'dist-electron'), path.join(appDir, 'dist-electron'));
fs.copyFileSync(path.join(desktopDir, 'package.json'), path.join(appDir, 'package.json'));

// If app.asar still exists, extract node_modules from it once or rename it to app.asar.bak
const asarPath = path.join(resourcesDir, 'app.asar');
const bakPath = path.join(resourcesDir, 'app.asar.bak');
if (fs.existsSync(asarPath) && !fs.existsSync(bakPath)) {
  fs.renameSync(asarPath, bakPath);
}

// Ensure electron-updater stub or node_modules is available
const nmDir = path.join(appDir, 'node_modules', 'electron-updater');
if (!fs.existsSync(nmDir)) {
  fs.mkdirSync(nmDir, { recursive: true });
  const EventEmitter = 'const { EventEmitter } = require("events"); const u = new EventEmitter(); u.checkForUpdates = async () => ({ updateInfo: null }); u.downloadUpdate = async () => {}; u.quitAndInstall = () => {}; module.exports = { autoUpdater: u };';
  fs.writeFileSync(path.join(nmDir, 'index.js'), EventEmitter, 'utf8');
  fs.writeFileSync(path.join(nmDir, 'package.json'), JSON.stringify({ name: 'electron-updater', main: 'index.js' }), 'utf8');
}

console.log(`Updated AegisRE Studio live application directory at ${appDir}`);
