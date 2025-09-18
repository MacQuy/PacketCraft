const { app, BrowserWindow } = require("electron");
const path = require("path");

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    autoHideMenuBar: true,
    resizable: false
  });

  win.loadFile(path.join(__dirname, "frontend/index.html"));
}

app.whenReady().then(createWindow);