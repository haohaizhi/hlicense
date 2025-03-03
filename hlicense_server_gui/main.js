//main.js
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');


// 获取应用根目录
const appPath = app.getAppPath();

function createWindow() {
    const win = new BrowserWindow({
        width: 800,
        height: 600,
		icon: path.join(appPath, 'icon.png'),
        webPreferences: {
            preload: path.join(appPath, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: true
        },
    });

    win.loadFile('index.html');

    // 打开开发者工具
     win.webContents.openDevTools();
}

// 去除尾部为 0 的字节
function removeTrailingZeros(buffer) {
    let lastNonZeroIndex = buffer.length - 1;
    while (lastNonZeroIndex >= 0 && buffer[lastNonZeroIndex] === 0) {
        lastNonZeroIndex--;
    }
    return buffer.slice(0, lastNonZeroIndex + 1);  // 截取有效部分
}

function calculateMD5(buffer) {
    const hash = crypto.createHash('md5');
    hash.update(buffer);
    return hash.digest('hex');  // 返回 MD5 哈希值的十六进制表示
}


function rsaDecrypt(privateKey, encryptedData) {
    const buffer = Buffer.from(encryptedData, 'base64');
    
    try {
        // 使用 PKCS#1 填充
        return crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING // 使用 PKCS#1 填充
            },
            buffer
        );
    } catch (err) {
        console.error("RSA 解密失败", err);
        throw err;
    }
}

// 用于 AES 解密的函数 (适用于 ECB 模式)
function aesDecrypt(aesKey, encryptedData) {

    // 检查密钥长度
    if (aesKey.length !== 16 && aesKey.length !== 24 && aesKey.length !== 32) {
        throw new Error('Invalid key length. Key must be 16, 24, or 32 bytes.');
    }

    // 创建解密器
    const blockSize = 16; // AES 的块大小是 16 字节
    const paddingLength = blockSize - (encryptedData.length % blockSize);
    const padding = Buffer.alloc(paddingLength, paddingLength); // 创建填充数据
    encryptedData = Buffer.concat([encryptedData, padding]);


    const decipher = crypto.createDecipheriv('aes-256-ecb', aesKey, null);

    // 解密数据
    let decrypted = decipher.update(encryptedData);
    let cleanedData = removeTrailingZeros(decrypted);
    // console.log("cleanedData", cleanedData.toString('hex'));

    const md5Value = calculateMD5(cleanedData);
    // console.log("MD5:", md5Value); 

    return md5Value;
}


// 使用私钥加密
const encryptWithPrivateKey = (privateKey, message) => {
    try {
        // 使用私钥加密数据
        const encrypted = crypto.privateEncrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING, // 使用 PKCS1 填充
            },
            Buffer.from(message, 'utf8') // 将消息转换为 Buffer
        );

        // 返回 Base64 编码的加密数据（每 64 字符换行）
        const base64Data = encrypted.toString('base64');
        const formattedBase64 = base64Data.match(/.{1,64}/g).join('\n'); // 每 64 字符换行
        return formattedBase64;
    } catch (err) {
        console.error('私钥加密失败:', err);
        throw new Error('私钥加密失败');
    }
};

// 处理文件读取和解密的函数
ipcMain.handle('decrypt-file', async (event, filePath, privateKeyPath, days) => {
    try {
        console.info('filePath',filePath);
        console.info('privateKeyPath',privateKeyPath);
        console.info('days',days);
        // 读取文件内容，假设是 base64 编码的字符串
        // console.log('机器码文件',filePath);
        const fileContent = await fs.promises.readFile(filePath, 'utf-8');

        // 将文件内容转为 Buffer
        const buffer = Buffer.from(fileContent, 'base64');

        // console.log('buff',buffer);

        // 第一步：用 RSA 解密获得 AES 密钥（256 字节）
        const rsaPrivateKey = fs.readFileSync(privateKeyPath, 'utf-8');
        const aesKey = rsaDecrypt(rsaPrivateKey, buffer.slice(0, 256)); // 获取 AES 密钥

        // console.log('AESkey',aesKey);

        // 第二步：获取数据长度
        const dataLength = buffer.length - 260;
        // console.log('dataLength',dataLength);
        // 第三步：使用 AES 解密数据
        
        const encryptedData = buffer.slice(260, 260 + dataLength);
        const decryptedData = aesDecrypt(aesKey, encryptedData);


        // 获取当前时间
        const createTime = Math.floor(Date.now() / 1000);

        // 计算结束时间
        
        const endTime = createTime + days * 24 * 60 * 60;
        if(days == 0)
            endTime = 0;

        const result = {
            CustomerName: 'iii-hong', 
            AuthorName: 'hongqiang', 
            ProjectName: 'test', 
            ESN: decryptedData, 
            CreateTime: createTime, 
            EndTime: endTime
        };

        const jsonString = JSON.stringify(result, null, 2); 
        console.info('jsonString',jsonString);

        // 使用 RSA 私钥加密 JSON 字符串
        const encryptedBase64 = encryptWithPrivateKey(rsaPrivateKey, jsonString);

        // 写入到文件
        const outputFilePath = path.join(appPath, `${decryptedData}.lic`); // 文件名
        fs.writeFileSync(outputFilePath, encryptedBase64); // 写入文件


        console.info('授权文件:', outputFilePath);

        // 返回解密后的数据
        return outputFilePath;

    } catch (err) {
        console.error('解密过程中出错:', err);
        throw new Error('解密失败');
    }
});

app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// 打开选择目录对话框
ipcMain.on('open-directory-dialog', (event) => {
    dialog.showOpenDialog({
        properties: ['openDirectory']
    }).then(result => {
        if (!result.canceled) {
            // 发送目录路径给渲染进程
            event.sender.send('selected-directory', result.filePaths[0]);
        }
    });
});

// 生成 RSA 密钥
ipcMain.handle('generate-keys', async (event, directory) => {
    try {
        const key = new NodeRSA({ b: 2048 });

        // 导出公钥为 PKCS#1 格式
        const publicKey = key.exportKey('pkcs1-public');  // 使用 pkcs1-public 导出公钥
        // 导出私钥为 PKCS#1 格式
        const privateKey = key.exportKey('pkcs1');        // 使用 pkcs1 导出私钥

        const publicKeyPath = path.join(directory, 'public_key.pem');
        const privateKeyPath = path.join(directory, 'private_key.pem');

        // 将公钥和私钥写入文件
        fs.writeFileSync(publicKeyPath, publicKey);
        fs.writeFileSync(privateKeyPath, privateKey);

        return { publicKeyPath, privateKeyPath };
    } catch (error) {
        console.error('生成密钥时出错:', error);
        return { error: error.message };
    }
});


// 打开文件选择对话框
ipcMain.on('open-file-dialog', (event, fileId) => {
    dialog.showOpenDialog({
        properties: ['openFile']
    }).then(result => {
        if (!result.canceled) {
            // 发送文件路径给渲染进程
            event.sender.send('file-selected', result.filePaths[0], fileId);
        }
    });
});

// 读取文件内容
ipcMain.handle('read-file-content', async (event, filePath) => {
    try {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        return content;
    } catch (err) {
        console.error('读取文件内容时出错:', err);
        throw err;
    }
});