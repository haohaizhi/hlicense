# 使用说明

主要针对需要授权的软件

## 直接调用程序方式

程序需要获取授权状态时，直接执行命令获取回显，通过回显内容判断是否处于授权状态

### 前提条件

设备授权成功，拥有以下文件
```shell
/etc/license/hlicense.lic
/etc/license/public_key.pem

/usr/bin/hlicense_client
```

### 代码示例
```c++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_license_status() {
    // 用于存储命令输出的缓冲区
    char buffer[128];
    
    // 通过popen执行命令并打开管道
    FILE *fp = popen("hlicense_client -v", "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return -1;  // 如果打开管道失败，返回错误
    }

    // 读取命令的输出
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // 如果回显中包含"true"（授权成功）
        if (strstr(buffer, "true") != NULL) {
            fclose(fp);  
            return 1;     
        }
        // 如果回显中包含"false"（授权失败）
        if (strstr(buffer, "false") != NULL) {
            fclose(fp); 
            return 0;    
        }
    }

    fclose(fp);  
    return -1;
}

int main() {
    int status = check_license_status();
    if (status == 1) {
        printf("License authorized successfully.\n");
    } else if (status == 0) {
        printf("License authorization failed.\n");
    } else {
        printf("Error occurred while checking license status.\n");
    }
    return 0;
}
```


## 使用动态链接库

程序需要获取授权状态时，直接执行函数，通过函数返回值判断处于授权状态

### 前提条件

设备授权成功，拥有以下文件
```shell
/etc/license/hlicense.lic
/etc/license/public_key.pem
```

### 代码示例

项目代码中包含动态库so以及头文件

```shell
libhlic.so
hlicense_client.h
```

```c++
#include <stdio.h>
#include <stdlib.h>

#include "hlicense_client.h"

int main()
{
	int status = validate_license();
    if (status == 0)
        printf("License authorized successfully.\n");
    else
        printf("License authorization failed.\n");
	return 0;
}
```

编译
```bash
g++ -o test test.cpp -L. -lhlic
```

测试
```bash
export LD_LIBRARY_PATH=./

./test
```


## Demo

Demo目录中的代码主要介绍RSA加密的使用示例，可以进行参考与学习。