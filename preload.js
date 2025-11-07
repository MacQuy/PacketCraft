const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
    chooseFolder: () => ipcRenderer.invoke("choose-folder"),
    getDownloadsPath: () => ipcRenderer.invoke("get-downloads-path")
});