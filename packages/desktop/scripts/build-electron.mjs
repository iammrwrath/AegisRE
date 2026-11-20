import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const srcDir = path.resolve(__dirname, '../electron');
const outDir = path.resolve(__dirname, '../dist-electron');
const distDir = path.resolve(__dirname, '../dist');

if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

fs.copyFileSync(path.join(srcDir, 'main.cjs'), path.join(outDir, 'main.cjs'));
fs.copyFileSync(path.join(srcDir, 'preload.cjs'), path.join(outDir, 'preload.cjs'));
fs.copyFileSync(path.join(srcDir, 'disassembler.cjs'), path.join(outDir, 'disassembler.cjs'));

const uiHtml = path.join(srcDir, 'ui.html');
if (fs.existsSync(uiHtml)) {
  if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
  }
  fs.copyFileSync(uiHtml, path.join(distDir, 'index.html'));
}

console.log('Electron main, preload & disassembler engine bundled into dist-electron/');
