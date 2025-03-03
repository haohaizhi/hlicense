#include <iostream>
#include <fstream>
#include <sstream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <vector>

#include "hlicense_client.h"
#include "cJSON.h"

#define HexPrint(_buf, _len) \
        {\
            int _m_i = 0;\
            char *_m_buf = (char *)(_buf);\
            int _m_len = (int)(_len);\
            printf("[%s:%d] \r\n", __FUNCTION__, __LINE__);\
            printf("***************************************************\n");\
            for(_m_i = 0; _m_i < _m_len; _m_i++)\
            {\
                printf("\033[32m%02x \033[0m", _m_buf[_m_i] & 0xff);\
                if(!((_m_i+1) % 16))  printf("\n");\
            }\
            printf("\nsize = %d\n***************************************************\n", _m_len);\
        }

#define AES_KEY_SIZE 32   // AES-256
#define AES_BLOCK_SIZE 16 // AES block size

#define RSA_KEY_SIZE 256   // RSA-2048


#define LICENSE_FILE "/etc/license/hlicense.lic"

// 错误处理
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// 生成 AES 密钥
void generate_aes_key(unsigned char *key) {
    if (!RAND_bytes(key, AES_KEY_SIZE)) {
        handle_errors();
    }
}

//计算Md5值
void calculate_md5(const char *str, unsigned char *result) {
    MD5_CTX mdContext;
    MD5_Init(&mdContext);
    MD5_Update(&mdContext, str, strlen(str));
    MD5_Final(result, &mdContext);
}

unsigned int aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, unsigned int size) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, AES_KEY_SIZE*8, &aes_key);
    
    unsigned int i = 0;
    for (i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_encrypt(plaintext + i, ciphertext + i, &aes_key);
    }
    return i;
}


void aes_decrypt(const unsigned char *ciphertext, const unsigned char *key, unsigned char *decryptedtext, unsigned int size) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, AES_KEY_SIZE*8, &aes_key);
    
    for (unsigned int i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_decrypt(ciphertext + i, decryptedtext + i, &aes_key);
    }
}

// 从文件加载RSA公钥
RSA* load_public_key(const std::string& pub_key_file) {
    FILE *pub_key_fp = fopen(pub_key_file.c_str(), "rb");
    if (!pub_key_fp) {
        std::cerr << "Error opening public key file" << std::endl;
        return nullptr;
    }
    RSA *rsa = PEM_read_RSAPublicKey(pub_key_fp, nullptr, nullptr, nullptr);
    fclose(pub_key_fp);
    return rsa;
}

// 使用 RSA 公钥 对 AES 密钥签名
std::string encrypt_with_public_key(RSA *rsa, const char *message, int msglen) {
    if (!rsa) {
        std::cerr << "Invalid RSA key." << std::endl;
        return "";
    }

    // 设置加密缓冲区大小
    int rsa_len = RSA_size(rsa);  // 获取RSA加密块的大小
    unsigned char *encrypted = new unsigned char[rsa_len];

    // 使用公钥加密数据
    int result_len = RSA_public_encrypt(msglen, 
                                        reinterpret_cast<const unsigned char *>(message),
                                        encrypted, 
                                        rsa, 
                                        RSA_PKCS1_PADDING);

    if (result_len == -1) {
        std::cerr << "RSA encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        delete[] encrypted;
        return "";
    }

    // 将加密后的数据转换为字符串
    std::string encrypted_str(reinterpret_cast<char *>(encrypted), result_len);

    delete[] encrypted;
    return encrypted_str;
}

// 使用公钥解密
std::string decrypt_with_public_key(RSA *rsa, const std::string& encrypted_message) {
    int rsa_len = RSA_size(rsa);
    std::vector<unsigned char> decrypted(rsa_len);
    int result = RSA_public_decrypt(encrypted_message.size(), (unsigned char*)encrypted_message.c_str(), decrypted.data(), rsa, RSA_PKCS1_PADDING);
    if (result == -1) {
        std::cerr << "Error decrypting with public key" << std::endl;
        return "";
    }
    return std::string(decrypted.begin(), decrypted.begin() + result);
}

std::string base64_encode(const char* input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    // 创建一个BASE64 BIO
    b64 = BIO_new(BIO_f_base64());
    // 创建一个内存BIO
    bio = BIO_new(BIO_s_mem());
    // 将两个BIO连接在一起
    bio = BIO_push(b64, bio);

    // 写入数据到BIO流
    BIO_write(bio, input, length);
    // 刷新BIO流
    BIO_flush(bio);
    // 获取内存中的数据
    BIO_get_mem_ptr(bio, &bufferPtr);

    // 创建一个新的字符串，包含Base64编码的结果
    std::string encoded(bufferPtr->data, bufferPtr->length);

    // 释放BIO资源
    BIO_free_all(bio);

    return encoded;
}
// Base64解码
std::string base64_decode(const std::string& input) {
    BIO *bio, *b64;
    std::vector<char> buffer(input.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);

    int len = BIO_read(bio, buffer.data(), input.length());
    BIO_free_all(bio);

    return std::string(buffer.data(), len);
}

// 生成 机器码 文件
int generate_sn_file(const char *hardware_info, int hard_len,const char *pub_key_file,const char* sn_file_path) {
    unsigned char aes_key[AES_KEY_SIZE];

    unsigned char ciphertext[512];  // 假设加密后的数据不超过 512 字节

    // 1. 生成 AES 密钥
    generate_aes_key(aes_key);

    // 2. 使用 RSA 公钥签名 AES 密钥
    RSA *rsa = nullptr;
    std::string rsa_encrypted;
    rsa = load_public_key(pub_key_file);  // 加载公钥
    if (!rsa) {
        std::cerr << "Failed to load public key." << std::endl;
        return 1;
    }
    rsa_encrypted = encrypt_with_public_key(rsa, (const char*)aes_key,AES_KEY_SIZE);  // 使用公钥加密
    if (rsa_encrypted.empty()) {
        std::cerr << "Failed to encrypt message." << std::endl;
        return 1;
    }


    // 3. 使用 AES 加密硬件信息
    // printf("length: %d\n", hard_len);
    unsigned int encrypted_length = aes_encrypt((unsigned char*)hardware_info, aes_key, ciphertext, hard_len);

    // 5. 输出 SN 码
    // HexPrint(rsa_encrypted.c_str(),rsa_encrypted.length());
    // printf("SN length: %d\n", encrypted_length);
    // HexPrint(ciphertext,encrypted_length);

    char SN_char[1024] = {0};  // SN = RsaSign(AES Key) + Length(AES(HardwareInfo)) + AES(HardwareInfo) 假设数据不会超过1024字节
    memcpy(SN_char, rsa_encrypted.c_str(), rsa_encrypted.length());
    memcpy(SN_char + rsa_encrypted.length(), &encrypted_length, sizeof(int));
    memcpy(SN_char + rsa_encrypted.length() + sizeof(int), ciphertext, encrypted_length);

    int SN_length = RSA_KEY_SIZE + sizeof(int) + encrypted_length;

    // 编码为 Base64 并保存到授权文件
    std::string encoded = base64_encode(SN_char,SN_length);
    std::ofstream ofs(sn_file_path);
    if (!ofs) {
        std::cerr << "Failed to open device.did file for writing." << std::endl;
        return 1;
    }
    ofs << encoded;
    ofs.close();

    std::cout << "SN file:" << sn_file_path <<std::endl;
    return 0;
}


void remove_spaces_and_tabs(char *str) {
    int i = 0, j = 0;
    while (str[i]) {
        // 如果字符不是空格（' '）且不是制表符（'\t'），则保留
        if (str[i] != ' ' && str[i] != '\t') {
            str[j++] = str[i];
        }
        i++;
    }
    str[j] = '\0';  // 添加字符串结尾符
}


int shellcmd(const char* cmd, char* buff, int size)
{
    char temp[256];
    FILE* fp = NULL;
    int len;
   
    fp = popen(cmd, "r");
    if(fp == NULL)
    {
        return -1;
    }

    while(fgets(temp, sizeof(temp), fp) != NULL)
    {
        len = strlen(temp);
        if(len < size)
        {
            memcpy(buff, temp, len-1);
            // strcpy(buff, temp);
        }
        else
        {
            break;
        }
    }  
    pclose(fp);
    remove_spaces_and_tabs(temp);
    return strlen(temp);
}

// 获取网卡 MAC 地址
int get_mac_address(char* mac_address, const char* interface) {

    // 创建一个 socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        // perror("Socket error");
        return -1;
    }

    // 设置接口信息
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name) - 1);

    // 获取 MAC 地址
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        close(sock);
        // perror("ioctl error");
        return -1;
    }

    // 格式化 MAC 地址为字符串
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(mac_address,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 关闭 socket
    close(sock);

    return strlen(mac_address);
}

// 获取时间的字符串表示
void get_time_string(char *time_string, time_t now) {
    struct tm *tm_info = localtime(&now);
    strftime(time_string, 20, "%Y-%m-%d %H:%M:%S", tm_info); // 格式化为 "YYYY-MM-DD HH:MM:SS"
}

// 将 MD5 值转换为十六进制字符串
void md5_to_hex_string(const unsigned char *md5, char *hex_string) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", md5[i]);
    }
    hex_string[MD5_DIGEST_LENGTH * 2] = '\0'; // 添加字符串结束符
}

// 创建机器码文件
void create_machine_code(const char *filename, const char *network_card) {

    char mac_address[18] = {0};
    unsigned int mac_len = get_mac_address(mac_address,network_card);
    if(mac_len <= 0 )
            sprintf(mac_address,"%s","00:00:00:00:00:00");

    // 获取 CPU 序列号
    // 获取主板序列号
    // 获取硬盘序列号
    char cpu_sn[128] = {0};
    char mainboard_sn[128] = {0};
    char disk_sn[128] = {0};
    unsigned int cpusn_len,mainboardsn_len,disksn_len;

    cpusn_len = shellcmd("dmidecode -t processor | grep 'ID' | tail -n 1", cpu_sn, sizeof(cpu_sn));
    if(cpusn_len <= 0 )
        sprintf(cpu_sn,"%s","Unknown_CPU_SN");
    mainboardsn_len = shellcmd("dmidecode -t baseboard | grep 'Serial Number' | tail -n 1", mainboard_sn, sizeof(mainboard_sn));
    if(mainboardsn_len <= 0 )
        sprintf(cpu_sn,"%s","Unknown_Mainboard_SN");
    disksn_len = shellcmd("lsblk -o NAME,SERIAL | grep -E 'sda' | tail -n 1", disk_sn, sizeof(disk_sn));
    if(disksn_len <= 0 )
        sprintf(cpu_sn,"%s","Unknown_Disk_SN");
    
    char hardware_info[512] = {0};
    memcpy(hardware_info, cpu_sn, cpusn_len);
    memcpy(hardware_info + cpusn_len, mainboard_sn, mainboardsn_len);
    memcpy(hardware_info + cpusn_len + mainboardsn_len, disk_sn, disksn_len);
    memcpy(hardware_info + cpusn_len + mainboardsn_len + disksn_len, mac_address, mac_len);

    // printf("hardinfo_len:%d\n",strlen(hardware_info));
    // printf("info:%s\n",hardware_info);
    // unsigned char result[MD5_DIGEST_LENGTH];
    // calculate_md5(hardware_info, result);
    // HexPrint(result,MD5_DIGEST_LENGTH);

    // 生成 SN 码
    int ret = generate_sn_file(hardware_info, strlen(hardware_info),RSA_PUBKEY_FILE, filename);
    if(ret != 0 )
    {
        printf("Failed to create device.did file for license!.\n");
    }
}


// 显示授权状态
void display_license_status() {
    // 这里调用实际的创建授权文件的逻辑
    std::ifstream ifs(LICENSE_FILE);
    if (!ifs) {
        std::cerr << "Failed to open "<< LICENSE_FILE << " file for reading." << std::endl;
        return;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string encoded = buffer.str();
    ifs.close();

    std::string encrypted = base64_decode(encoded);

    RSA *rsa = nullptr;
    rsa = load_public_key(RSA_PUBKEY_FILE);  // 加载公钥
    if (!rsa) {
        std::cerr << "Failed to load public key." << std::endl;
        return;
    }
    std::string decrypted = decrypt_with_public_key(rsa, encrypted);  // 使用公钥解密
    if (decrypted.empty()) {
        std::cerr << "Failed to decrypt message." << std::endl;
        return;
    }

    cJSON *json = cJSON_Parse(decrypted.c_str());
    if (json == NULL) {
        fprintf(stderr, "Error parsing JSON string\n");
        return;
    }

    cJSON *create_time = cJSON_GetObjectItem(json, "CreateTime");
    if(!create_time) {
        printf("get create_time failed!\n");
        return;
    }
    cJSON *end_time = cJSON_GetObjectItem(json, "EndTime");
    if(!end_time) {
        printf("get end_time failed!!\n");
        return;
    }

    char create_time_char[20], end_time_char[20];
    get_time_string(create_time_char, create_time->valuedouble);
    get_time_string(end_time_char, end_time->valuedouble);

    // 创建新的字段
    cJSON *new_create_time = cJSON_CreateString(create_time_char);
    cJSON *new_end_time = cJSON_CreateString(end_time_char);

    // 替换
    cJSON_ReplaceItemInObject(json, "CreateTime", new_create_time);
    cJSON_ReplaceItemInObject(json, "EndTime", new_end_time);
    
    // 生成格式化的 JSON 字符串（带缩进和换行）
    char *formatted_json = cJSON_Print(json);
    if (formatted_json == NULL) {
        fprintf(stderr, "Error formatting JSON\n");
        cJSON_Delete(json);
        return;
    }

    // 打印格式化后的 JSON 字符串
    printf("%s\n", formatted_json);

    // 释放内存
    free(formatted_json);
    cJSON_Delete(json);
}

// 导入授权文件
int import_license(const char *license_file) {  

   //获取设备硬件信息
    char mac_address[18] = {0};
    unsigned int mac_len = get_mac_address(mac_address,INTERFACE_NAME);
    if(mac_len <= 0 )
            sprintf(mac_address,"%s","00:00:00:00:00:00");
    char cpu_sn[128] = {0};
    char mainboard_sn[128] = {0};
    char disk_sn[128] = {0};
    unsigned int cpusn_len,mainboardsn_len,disksn_len;

    cpusn_len = shellcmd("dmidecode -t processor | grep 'ID' | tail -n 1", cpu_sn, sizeof(cpu_sn));
    if(cpusn_len <= 0 )
        sprintf(cpu_sn,"%s","Unknown_CPU_SN");
    mainboardsn_len = shellcmd("dmidecode -t baseboard | grep 'Serial Number' | tail -n 1", mainboard_sn, sizeof(mainboard_sn));
    if(mainboardsn_len <= 0 )
        sprintf(cpu_sn,"%s","Unknown_Mainboard_SN");
    disksn_len = shellcmd("lsblk -o NAME,SERIAL | grep -E 'sda' | tail -n 1", disk_sn, sizeof(disk_sn));
    if(disksn_len <= 0 )
        sprintf(cpu_sn,"%s","Unknown_Disk_SN");
    
    char hardware_info[512] = {0};
    memcpy(hardware_info, cpu_sn, cpusn_len);
    memcpy(hardware_info + cpusn_len, mainboard_sn, mainboardsn_len);
    memcpy(hardware_info + cpusn_len + mainboardsn_len, disk_sn, disksn_len);
    memcpy(hardware_info + cpusn_len + mainboardsn_len + disksn_len, mac_address, mac_len);
    unsigned char result[MD5_DIGEST_LENGTH];
    calculate_md5(hardware_info, result);

    char esn_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex_string(result, esn_hex);

    //获取License中硬件信息、时间信息
    std::ifstream ifs(license_file);
    if (!ifs) {
        std::cerr << "Failed to open "<< license_file << " file for reading." << std::endl;
        return 1;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string encoded = buffer.str();
    ifs.close();

    std::string encrypted = base64_decode(encoded);

    RSA *rsa = nullptr;
    rsa = load_public_key(RSA_PUBKEY_FILE);  // 加载公钥
    if (!rsa) {
        std::cerr << "Failed to load public key." << std::endl;
        return 1;
    }
    std::string decrypted = decrypt_with_public_key(rsa, encrypted);  // 使用公钥解密
    if (decrypted.empty()) {
        std::cerr << "Failed to decrypt message." << std::endl;
        return 1;
    }

    cJSON *json = cJSON_Parse(decrypted.c_str());
    if (json == NULL) {
        fprintf(stderr, "Error parsing JSON string\n");
        return 1;
    }

    cJSON *ESN = cJSON_GetObjectItem(json, "ESN");
    if(!ESN) {
        printf("get ESN failed!\n");
        return 1;
    }

    cJSON *create_time = cJSON_GetObjectItem(json, "CreateTime");
    if(!create_time) {
        printf("get create_time failed!\n");
        return 1;
    }
    cJSON *end_time = cJSON_GetObjectItem(json, "EndTime");
    if(!end_time) {
        printf("get end_time failed!!\n");
        return 1;
    }
    char esn_hex_lic[MD5_DIGEST_LENGTH * 2 + 1];
    memcpy(esn_hex_lic, ESN->valuestring, MD5_DIGEST_LENGTH * 2);

    //判断硬件信息是否符合
    int result_md5 = memcmp(esn_hex, esn_hex_lic, MD5_DIGEST_LENGTH * 2);
    if (result_md5 != 0)
    {
        printf("false\n");
        return 1;
    }

    //判断时间是否符合
    if(end_time->valuedouble == 0)
    {
        printf("true\n");
        rename(license_file, LICENSE_FILE);
        return 0;
    }

    time_t now = time(NULL);
    if((now >= create_time->valuedouble) && (now <= end_time->valuedouble))
    {
        printf("true\n");
        rename(license_file, LICENSE_FILE);
        return 0;
    }
    printf("false\n");
    return 1;
}

// 校验授权状态
int validate_license() {
    return import_license(LICENSE_FILE);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [options]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  -c [-f filename]                     Create a machine code file\n");
        fprintf(stderr, "  -j                                   Display current license status\n");
        fprintf(stderr, "  -v                                   Validate license\n");
        fprintf(stderr, "  -i <license_file>                   Import license file\n");
        return 1;
    }

    int opt;
    const char *filename = DEVICE_SN_FILE; // 默认文件名
    const char *network_card = INTERFACE_NAME; // 默认网卡

    while ((opt = getopt(argc, argv, "cf:jvi:")) != -1) {
        switch (opt) {
            case 'c':
                // 处理 -c 命令
                while ((opt = getopt(argc, argv, "f:")) != -1) {
                    switch (opt) {
                        case 'f':
                            filename = optarg;
                            break;
                        default:
                            fprintf(stderr, "Usage: %s -c [-f filename]\n", argv[0]);
                            return 1;
                    }
                }
                create_machine_code(filename, network_card);
                break;
            case 'j':
                display_license_status();
                break;
            case 'v':
                validate_license();
                break;
            case 'i':
                if (optarg == NULL) {
                    fprintf(stderr, "Usage: %s -i <license_file>\n", argv[0]);
                    return 1;
                }
                import_license(optarg);
                break;
            default:
                fprintf(stderr, "Unknown command: %c\n", opt);
                return 1;
        }
    }

    return 0;
}


