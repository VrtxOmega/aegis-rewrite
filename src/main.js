/**
 * Aegis ReWrite — Electron Main Process
 * Cross-platform: spawns Flask backend, manages window lifecycle.
 */
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');

// CRITICAL: Disable Electron's file cache so CSS/JS changes always load from disk
app.commandLine.appendSwitch('disable-http-cache');
app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');

const FLASK_PORT = 5055;
const FLASK_URL = `http://127.0.0.1:${FLASK_PORT}`;
let flaskProcess = null;
let mainWindow = null;

// ═══════════════════════════════════════════
// FLASK BACKEND SPAWNER (cross-platform)
// ═══════════════════════════════════════════

function getBackendPath() {
    // In dev: backend/ next to package.json
    // In prod: resources/backend/
    const devPath = path.join(__dirname, '..', 'backend');
    const prodPath = path.join(process.resourcesPath || '', 'backend');
    const fs = require('fs');
    if (fs.existsSync(path.join(devPath, 'app.py'))) return devPath;
    if (fs.existsSync(path.join(prodPath, 'app.py'))) return prodPath;
    return devPath;
}

function getPythonCmd(backendDir) {
    const fs = require('fs');
    if (process.platform === 'win32') {
        const venvPy = path.join(backendDir, 'venv', 'Scripts', 'python.exe');
        if (fs.existsSync(venvPy)) return venvPy;
        return 'python';
    } else {
        const venvPy = path.join(backendDir, 'venv', 'bin', 'python3');
        if (fs.existsSync(venvPy)) return venvPy;
        return 'python3';
    }
}

function startFlask() {
    const backendDir = getBackendPath();
    const pythonCmd = getPythonCmd(backendDir);
    const appPy = path.join(backendDir, 'app.py');

    console.log(`[ReWrite] Starting Flask: ${pythonCmd} ${appPy}`);

    flaskProcess = spawn(pythonCmd, [appPy], {
        cwd: backendDir,
        env: { ...process.env, PYTHONUNBUFFERED: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
    });

    flaskProcess.stdout.on('data', d => console.log(`[Flask] ${d}`));
    flaskProcess.stderr.on('data', d => console.error(`[Flask] ${d}`));
    flaskProcess.on('exit', code => {
        console.log(`[Flask] exited with code ${code}`);
        flaskProcess = null;
    });
}

function waitForFlask(retries = 30) {
    return new Promise((resolve, reject) => {
        const check = (n) => {
            http.get(`${FLASK_URL}/api/health`, res => {
                resolve(true);
            }).on('error', () => {
                if (n <= 0) return reject(new Error('Flask did not start'));
                setTimeout(() => check(n - 1), 300);
            });
        };
        check(retries);
    });
}

// ═══════════════════════════════════════════
// WINDOW CREATION
// ═══════════════════════════════════════════

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 860,
        minWidth: 900,
        minHeight: 600,
        backgroundColor: '#020204',
        icon: path.join(__dirname, '..', 'assets', 'icon.ico'),
        titleBarStyle: 'hidden',
        frame: false,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
    });

    // Clear cached CSS/JS so edits always take effect on restart
    mainWindow.webContents.session.clearCache().then(() => {
        mainWindow.loadFile(path.join(__dirname, 'index.html'));
    });

    mainWindow.on('closed', () => { mainWindow = null; });
}

// ═══════════════════════════════════════════
// IPC HANDLERS
// ═══════════════════════════════════════════

const activeRequests = new Map();

ipcMain.handle('backend:get', async (event, endpoint) => {
    try {
        const response = await fetch(`${FLASK_URL}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`[IPC] GET ${endpoint} failed:`, error.message);
        return { error: error.message };
    }
});

ipcMain.handle('backend:post', async (event, endpoint, data, reqId) => {
    const controller = new AbortController();
    if (reqId) activeRequests.set(reqId, controller);
    
    try {
        const response = await fetch(`${FLASK_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            signal: controller.signal
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        if (error.name === 'AbortError') return { abort: true, error: 'Aborted by user' };
        console.error(`[IPC] POST ${endpoint} failed:`, error.message);
        return { error: error.message };
    } finally {
        if (reqId) activeRequests.delete(reqId);
    }
});

ipcMain.handle('backend:abort', (event, reqId) => {
    const controller = activeRequests.get(reqId);
    if (controller) {
        controller.abort();
        activeRequests.delete(reqId);
    }
});

ipcMain.handle('dialog:open-directory', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
        properties: ['openDirectory'],
        title: 'Select Project Folder',
    });
    if (result.canceled || !result.filePaths.length) return null;
    return result.filePaths[0];
});

ipcMain.handle('window:minimize', () => mainWindow?.minimize());
ipcMain.handle('window:maximize', () => {
    if (mainWindow?.isMaximized()) mainWindow.unmaximize();
    else mainWindow?.maximize();
});
ipcMain.handle('window:close', () => mainWindow?.close());

// ── App state persistence ──
const fs = require('fs');
const PREFS_PATH = path.join(app.getPath('userData'), 'aegis-prefs.json');

function loadPrefs() {
    try {
        return JSON.parse(fs.readFileSync(PREFS_PATH, 'utf8'));
    } catch { return {}; }
}

function savePrefs(prefs) {
    fs.writeFileSync(PREFS_PATH, JSON.stringify(prefs, null, 2));
}

ipcMain.handle('app:getPlatform', () => process.platform);

ipcMain.handle('app:getLastFolder', () => {
    return loadPrefs().lastFolder || null;
});

ipcMain.handle('app:saveLastFolder', (event, folderPath) => {
    const prefs = loadPrefs();
    prefs.lastFolder = folderPath;
    savePrefs(prefs);
});

ipcMain.handle('app:getEditorPref', () => {
    return loadPrefs().editorPref || 'vscode';
});

ipcMain.handle('app:saveEditorPref', (event, pref) => {
    const prefs = loadPrefs();
    prefs.editorPref = pref;
    savePrefs(prefs);
});

ipcMain.handle('editor:open', async (event, filePath, line) => {
    const prefs = loadPrefs();
    const editor = prefs.editorPref || 'vscode';
    const { exec } = require('child_process');
    if (editor === 'vscode') {
        exec(`code --goto "${filePath}:${line || 1}"`);
    } else if (editor === 'cursor') {
        exec(`cursor --goto "${filePath}:${line || 1}"`);
    }
});

// ═══════════════════════════════════════════
// APP LIFECYCLE
// ═══════════════════════════════════════════

app.whenReady().then(async () => {
    startFlask();
    try {
        await waitForFlask();
        console.log('[ReWrite] Flask backend ready');
    } catch (e) {
        console.error('[ReWrite] Flask failed to start:', e.message);
    }
    createWindow();
});

app.on('window-all-closed', () => {
    if (flaskProcess) {
        flaskProcess.kill();
        flaskProcess = null;
    }
    app.quit();
});

app.on('before-quit', () => {
    if (flaskProcess) {
        flaskProcess.kill();
        flaskProcess = null;
    }
});
