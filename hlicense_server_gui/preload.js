// preload.js
const {contextBridge, ipcRenderer, remote, shell } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    openDirectoryDialog: () => ipcRenderer.send('open-directory-dialog'),
    onSelectedDirectory: (callback) => ipcRenderer.on('selected-directory', callback),
    generateKeys: (directory) => ipcRenderer.invoke('generate-keys', directory),


    openFileDialog: (fileId) => ipcRenderer.send('open-file-dialog', fileId),
    onFileSelected: (callback) => ipcRenderer.on('file-selected', callback),
    readFileContent: (filePath) => ipcRenderer.invoke('read-file-content', filePath),
    decryptFile: (filePath, privateKeyPath, days) => ipcRenderer.invoke('decrypt-file', filePath, privateKeyPath, days),
});


