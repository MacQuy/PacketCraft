const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const path = require("path");
const os = require("os");

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, "preload.js"),
    },
    autoHideMenuBar: true
  });

  win.loadFile(path.join(__dirname, "frontend/index.html"));
}


ipcMain.handle("choose-folder", async () => {
  const result = await dialog.showOpenDialog({ properties: ["openDirectory"] });
  if (result.canceled) return null;
  return result.filePaths[0];
});


ipcMain.handle("get-downloads-path", () => {
  return path.join(os.homedir(), "Downloads");
});

app.whenReady().then(createWindow);