const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegis', {
  openFile: () => ipcRenderer.invoke('dialog:openFile'),
  getLatestTarget: () => ipcRenderer.invoke('aegis:getLatestTarget'),
  analyzeTarget: (filePath) => ipcRenderer.invoke('aegis:analyzeTarget', filePath),
  disassembleAt: (filePath, address, size) =>
    ipcRenderer.invoke('aegis:disassembleAt', { filePath, address, size }),
  generateReport: (analysisData, options) =>
    ipcRenderer.invoke('aegis:generateReport', { analysisData, options }),
  saveReport: (payload) => ipcRenderer.invoke('aegis:saveReport', payload),
  getGhidraStatus: () => ipcRenderer.invoke('aegis:ghidraStatus'),
  getTheme: () => ipcRenderer.invoke('theme:get'),
  setTheme: (theme) => ipcRenderer.invoke('theme:set', theme),
  getVersion: () => ipcRenderer.invoke('app:version'),
  checkForUpdates: (token) => ipcRenderer.invoke('updater:check', token),
  hasConfiguredToken: () => ipcRenderer.invoke('updater:hasToken'),
  downloadUpdate: () => ipcRenderer.invoke('updater:download'),
  installUpdate: () => ipcRenderer.invoke('updater:install'),
  onUpdaterStatus: (callback) => {
    const handler = (event, val) => callback(val);
    ipcRenderer.on('updater:status', handler);
    return () => ipcRenderer.removeListener('updater:status', handler);
  },
  platform: process.platform,
});
