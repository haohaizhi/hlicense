# Hlicense

## 简介

Hlicense提供了一套完整的授权管理解决方案，支持许可证的导入、验证、及硬件绑定，旨在为软件开发者提供一个高效、安全的授权管理工具。


```bash
# ubuntu/debian10
sudo apt-get install libssl-dev

# centos
sudo yum install openssl-devel

```

### 1、授权验证逻辑

采用RSA+AES加密方式

RSA-2048

AES-128

#### 客户端

```bash
# 客户端获取硬件信息（CPU序列号、主板序列号、硬盘序列号、网卡MAC地址）
HardwareInfo = CPU SN + MainBoard SN + DISK SN + MAC

# 客户端将硬件信息采用AES方式进行加密，同时采用RSA对AES秘钥加签，将信息封装
SN = RsaSign(AES Key) + Length(AES(HardwareInfo)) + AES(HardwareInfo)

# 将封装后的信息使用base64编码写入 《硬件信息文件》

```

#### 服务端

```bash
# 服务端使用base64解码 《硬件信息文件》

# 服务端解签AES Key，然后使用AES key解密硬件信息，并生成Md5值作为设备序列号ESN
AES Key = RsaVerify(RsaSign(AES Key))

ESN = MD5(HardwareInfo) 

# 服务端将授权时间与各种信息封装成JSON，并进行RSA加签
{
	"CustomerName":	"iii-hong",
	"AuthorName":	"hongqiang",
	"ProjectName":	"test",
	"ESN":	"d3493559223b2fb18fc609b69b91d4cd",
	"CreateTime":	"2025-02-10 15:05:47",
	"EndTime":	"2025-02-20 15:05:47"
}

# 将封装后的信息使用base64编码写入 《授权文件》
```

#### 许可证校验

```bash
# 客户端使用base64解码 《授权文件》

# 客户端使用RSA解签获取JSON格式，并获得设备序列号的MD5值以及授权时间

# 客户端获取设备信息后生成MD5与设备序列号进行比对

# 客户端获取当前时间与授权时间进行比对

```

### 2、客户端使用说明

客户端需要有和服务端对应的RSA公钥

```bash
# 命令帮助
Usage: ./hlicense_client <command> [options]
Commands:
  -c [-f filename]        Create a machine code file
  -j                      Display current license status
  -v                      Validate license
  -i <license_file>       Import license file

# 生成《硬件信息文件》，需要提交给服务端获取授权文件
./hlicense_client -c     //默认路径/etc/license/device.did
./hlicense_client -c -f device-210.did

# 以JSON格式打印当前授权信息
./hlicense_client -j

# 查询授权状态
./hlicense_client -v

# 导入授权文件
./hlicense_client -i d3493559223b2fb18fc609b69b91d4cd.lic

```

### 3、服务端使用说明

服务端需要有和客户端端对应的RSA私钥

```bash
# 命令帮助
Usage: ./hlicense_server <command> [options]
Commands:
  new <public_key.pem> <private_key.pem>   Generate a new key pair
  create <device.did> [-t days] [-p project_name] [-k private_key_path]   Create a license file
  display <device.did> [-k private_key_path] Decrypt and display license information


# 生成一对RSA秘钥，可以指定秘钥文件的名字
./hlicense_server new public_key.pem private_key.pem


# 基于《硬件信息文件》生成《授权文件》
./hlicense_server create ./device.did  //默认授权30天

./hlicense_server create ./device.did -t 90     //授权90天

./hlicense_server create ./device.did -t 0      //永久授权


# 打印《硬件信息》
./hlicense_server display ./device.did
```

### 4、授权库使用
[详细请看Use目录](./use/README.md)


### 5、可视化服务端
可以使用生成RSA秘钥按钮生成一对秘钥

或者对 《硬件信息文件》进行授权然后生成《授权文件》供客户端使用



### 6、问题

目前程序授权验证对时间没有做其他更复杂的操作，完全相信用户设备的时间，这种情况下，用户可以手动更改时间来避免授权到期问题

#### 解决思路

* 针对联网运行的软件与设备，可以在校验时间时，选择从公网某个服务器获取时间，从而保证时间的可靠性

具体要修改的代码：
```c++
int import_license(const char *license_file) {
    ......
    ......
    time_t now = time(NULL);    //此处修改为从公网获取时间
    if((now >= create_time->valuedouble) && (now <= end_time->valuedouble))
    {
        printf("true\n");
        rename(license_file, LICENSE_FILE);
        return 0;
    }
    ......
    ......
}
```

* 针对离线环境，可以说是很难防的，当校验逻辑被了解后总会用办法绕过，只能提供一种思路，可以每次校验时记录当前时间、运行时间，并加密的写入到另一个文件中。然后每次都校验成功后，对这两个文件的时间都进行更新。后续判断是否过期时可以结合记录的时间进行判断，来看用户知否篡改了时间。这种方式也不是没办法破解，用户只需保留最开始授权成功时的环境，然后整个还原就行了。

* 针对离线环境，可以只提供永久授权，反正是跟硬件绑定的。