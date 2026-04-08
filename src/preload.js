/**
 * Aegis ReWrite — Preload Bridge v2
 * Exposes exactly the IPC surface the renderer needs. Nothing more.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegis', {
    // ── Backend HTTP proxy ──
    get:    (endpoint)           => ipcRenderer.invoke('backend:get', endpoint),
    post:   (endpoint, data, id) => ipcRenderer.invoke('backend:post', endpoint, data, id),
    abort:  (reqId)              => ipcRenderer.invoke('backend:abort', reqId),

    // ── Native dialogs ──
    selectFolder: () => ipcRenderer.invoke('dialog:open-directory'),

    // ── Window controls ──
    minimize: () => ipcRenderer.invoke('window:minimize'),
    maximize: () => ipcRenderer.invoke('window:maximize'),
    close:    () => ipcRenderer.invoke('window:close'),

    // ── App state ──
    getPlatform:     ()       => ipcRenderer.invoke('app:getPlatform'),
    getLastFolder:   ()       => ipcRenderer.invoke('app:getLastFolder'),
    saveLastFolder:  (path)   => ipcRenderer.invoke('app:saveLastFolder', path),
    getEditorPref:   ()       => ipcRenderer.invoke('app:getEditorPref'),
    saveEditorPref:  (pref)   => ipcRenderer.invoke('app:saveEditorPref', pref),

    // ── Editor integration ──
    openInEditor: (filePath, line) => ipcRenderer.invoke('editor:open', filePath, line),
});
