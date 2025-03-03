// renderer.js
document.getElementById('generateKeys').addEventListener('click', () => {
        window.electronAPI.openDirectoryDialog();
});


window.electronAPI.onSelectedDirectory((event, directory) => {
    if (directory) {
        console.log(`选择的目录: ${directory}`);
        // 生成密钥
        window.electronAPI.generateKeys(directory).then(result => {
            if (result.error) {
                console.error('生成密钥时出错:', result.error);
            } else {
                alert(`密钥已生成：\n公钥路径: ${result.publicKeyPath}\n私钥路径: ${result.privateKeyPath}`);
            }
        }).catch(error => {
            console.error('生成密钥时出错:', error);
        });
    }
});


const file1Input = document.getElementById('deviceDid');
const file2Input = document.getElementById('privateKey');

const selectFile1Button = document.getElementById('browseDeviceDid');
const selectFile2Button = document.getElementById('browsePrivateKey');

const daysSelect = document.getElementById('days');


// 选择文件1
selectFile1Button.addEventListener('click', () => {
    window.electronAPI.openFileDialog(1);  // 用参数区分是文件1还是文件2
});

// 选择文件2
selectFile2Button.addEventListener('click', () => {
    window.electronAPI.openFileDialog(2);
});


window.electronAPI.onFileSelected((event, file, fileId) => {
    const fileName = file.split('/').pop();
    if (fileId === 1) {
        file1Input.value = fileName;
    } else if (fileId === 2) {
        file2Input.value = fileName;
    }
});



document.getElementById('generateLicense').addEventListener('click', () => {
    window.electronAPI.decryptFile(file1Input.value,file2Input.value, daysSelect.value).then(result => {
        if (result.error) {
            // console.error('生成密钥时出错:', result.error);
            alert('授权文件生成错误: ' + result.error);
        } else {
            // console.log('解密后的数据:', result);
            alert('授权文件生成成功: ' + result); 
        }
    }).catch(error => {
        // console.error('生成密钥时出错:', error);
        alert('授权文件生成错误: ' + error.message); 
    });
});



