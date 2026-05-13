const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("desktopScanner", {
  buildCommand: (profile) => ipcRenderer.invoke("scanner:buildCommand", profile),
  detectProjectPath: () => ipcRenderer.invoke("scanner:detectProjectPath"),
  browseProjectPath: () => ipcRenderer.invoke("scanner:browseProjectPath"),
  runScan: (profile) => ipcRenderer.invoke("scanner:run", profile),
  stopScan: () => ipcRenderer.invoke("scanner:stop"),
  openPath: (targetPath) => ipcRenderer.invoke("scanner:openPath", targetPath),
  onLog: (handler) => ipcRenderer.on("scanner:log", (_event, payload) => handler(payload))
});
