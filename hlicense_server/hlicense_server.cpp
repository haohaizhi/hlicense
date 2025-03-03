#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

#include "hlicense_server.h"
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

#define RSA_KEY_LENGTH 2048
#define PUB_EXPONENT 65537


// 错误处理
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

//计算Md5值
void calculate_md5(const char *str, unsigned char *result) {
    MD5_CTX mdContext;
    MD5_Init(&mdContext);
    MD5_Update(&mdContext, str, strlen(str));
    MD5_Final(result, &mdContext);
}

void aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, unsigned int size) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, AES_KEY_SIZE*8, &aes_key);
    
    for (unsigned int i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_encrypt(plaintext + i, ciphertext + i, &aes_key);
    }
}


void aes_decrypt(const unsigned char *ciphertext, const unsigned char *key, unsigned char *decryptedtext, unsigned int size) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, AES_KEY_SIZE*8, &aes_key);
    
    for (unsigned int i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_decrypt(ciphertext + i, decryptedtext + i, &aes_key);
    }
}

// 生成RSA密钥对并保存到文件
bool generate_rsa_keypair(const std::string& pub_key_file, const std::string& pri_key_file) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, PUB_EXPONENT);

    if (RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, e, nullptr) != 1) {
        std::cerr << "Error generating RSA key pair" << std::endl;
        return false;
    }

    // 保存公钥
    FILE *pub_key_fp = fopen(pub_key_file.c_str(), "wb");
    if (!pub_key_fp) {
        std::cerr << "Error opening public key file for writing" << std::endl;
        return false;
    }
    PEM_write_RSAPublicKey(pub_key_fp, rsa);
    fclose(pub_key_fp);

    // 保存私钥
    FILE *pri_key_fp = fopen(pri_key_file.c_str(), "wb");
    if (!pri_key_fp) {
        std::cerr << "Error opening private key file for writing" << std::endl;
        return false;
    }
    PEM_write_RSAPrivateKey(pri_key_fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(pri_key_fp);

    RSA_free(rsa);
    BN_free(e);

    return true;
}

// 从文件加载RSA私钥
RSA* load_private_key(const std::string& pri_key_file) {
    FILE *pri_key_fp = fopen(pri_key_file.c_str(), "rb");
    if (!pri_key_fp) {
        std::cerr << "Error opening private key file" << std::endl;
        return nullptr;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(pri_key_fp, nullptr, nullptr, nullptr);
    fclose(pri_key_fp);
    return rsa;
}


//使用私钥解密
std::string decrypt_with_private_key(RSA *rsa, const std::string &encrypted_message) {
    if (!rsa) {
        std::cerr << "Invalid RSA key." << std::endl;
        return "";
    }

    int rsa_len = RSA_size(rsa);  // 获取RSA解密块的大小
    unsigned char *decrypted = new unsigned char[rsa_len];

    // 使用私钥解密数据
    int result_len = RSA_private_decrypt(encrypted_message.size(),
                                         reinterpret_cast<const unsigned char *>(encrypted_message.c_str()),
                                         decrypted, 
                                         rsa, 
                                         RSA_PKCS1_PADDING);

    if (result_len == -1) {
        std::cerr << "RSA decryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        delete[] decrypted;
        return "";
    }

    std::string decrypted_str(reinterpret_cast<char *>(decrypted), result_len);

    delete[] decrypted;
    return decrypted_str;
}

// 使用私钥加密
std::string encrypt_with_private_key(RSA *rsa, const std::string& message) {
    int rsa_len = RSA_size(rsa);
    std::vector<unsigned char> encrypted(rsa_len);
    int result = RSA_private_encrypt(message.size(), (unsigned char*)message.c_str(), encrypted.data(), rsa, RSA_PKCS1_PADDING);
    if (result == -1) {
        std::cerr << "Error encrypting with private key" << std::endl;
        return "";
    }
    return std::string(encrypted.begin(), encrypted.end());
}


// Base64编码
std::string base64_encode(const std::string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
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

// 将 MD5 值转换为十六进制字符串
void md5_to_hex_string(const unsigned char *md5, char *hex_string) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hex_string + (i * 2), "%02x", md5[i]);
    }
    hex_string[MD5_DIGEST_LENGTH * 2] = '\0'; // 添加字符串结束符
}

// 获取当前时间的字符串表示
void get_current_time_string(char *time_string) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_string, 20, "%Y-%m-%d %H:%M:%S", tm_info); // 格式化为 "YYYY-MM-DD HH:MM:SS"
}

// 计算结束时间（基于当前时间 + 授权天数）
void get_end_time_string(int days, char *end_time_string) {
    time_t now = time(NULL);
    time_t end_time = now + (days * 24 * 60 * 60); // 当前时间 + 授权天数
    struct tm *tm_info = localtime(&end_time);
    strftime(end_time_string, 20, "%Y-%m-%d %H:%M:%S", tm_info); // 格式化为 "YYYY-MM-DD HH:MM:SS"
}

// 生成 JSON 字符串
char *License_Json_set(const char *customer_name, const char *author_name, const char *project_name,
                       const unsigned char *esn_md5, int license_days) {
    // 创建 cJSON 对象
    cJSON *root = cJSON_CreateObject();

    // 添加字段
    cJSON_AddStringToObject(root, "CustomerName", customer_name);
    cJSON_AddStringToObject(root, "AuthorName", author_name);
    cJSON_AddStringToObject(root, "ProjectName", project_name);

    // 将 MD5 值转换为十六进制字符串
    char esn_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex_string(esn_md5, esn_hex);
    cJSON_AddStringToObject(root, "ESN", esn_hex);

    // 添加时间字段
    // char create_time[20], end_time[20];
    // get_current_time_string(create_time); // 创建时间
    // get_end_time_string(license_days, end_time); // 结束时间

    cJSON_AddNumberToObject(root,"CreateTime",time(NULL)); 
    if(license_days == 0)
        cJSON_AddNumberToObject(root,"EndTime",0);
    else
        cJSON_AddNumberToObject(root,"EndTime",time(NULL) + (license_days * 24 * 60 * 60));

    // cJSON_AddStringToObject(root, "Use", end_time);
    // 生成 JSON 字符串
    // char *json_string = cJSON_Print(root);
    char *json_string = cJSON_PrintUnformatted(root);

    // 释放 cJSON 对象
    cJSON_Delete(root);

    return json_string;
}

// 创建授权文件
void create_license(const char *device_did, int days, const char *project_name, const char *private_key_path) {
    printf("Creating license for device: %s\n", device_did);
    if (days == 0) {
        printf("  License Perpetual authorization !\n");
    }
    if (project_name != NULL) {
        printf("  Project name: %s\n", project_name);
    }
    if (private_key_path != NULL) {
        printf("  Private key path: %s\n", private_key_path);
    }
    // 这里调用实际的创建授权文件的逻辑
    std::ifstream ifs(device_did);
    if (!ifs) {
        std::cerr << "Failed to open device.did file for reading." << std::endl;
        return;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string encoded = buffer.str();
    ifs.close();

    std::string encrypted = base64_decode(encoded);

    if(encrypted.length() <= (RSA_KEY_SIZE + sizeof(int)))
    {
        std::cerr << "Invalid device.did file." << std::endl;
        return;
    }
    // 提取被 RSA 加密的 aeskey
    std::string aeskey = encrypted.substr(0, RSA_KEY_SIZE);

    // HexPrint(aeskey.c_str(),aeskey.length());

    // 提取被 AES 加密的 device_info
    std::string device_info = encrypted.substr(RSA_KEY_SIZE + sizeof(int));

    // HexPrint(device_info.c_str(),device_info.length());

    //解密获得AES秘钥
    RSA *rsa = nullptr;
    rsa = load_private_key(private_key_path);  // 加载私钥
    if (!rsa) {
        std::cerr << "Failed to load private key." << std::endl;
        return;
    }
    std::string Aeskey = decrypt_with_private_key(rsa, aeskey);  // 使用私钥解密
    if (Aeskey.empty()) {
        std::cerr << "Failed to get Aeskey." << std::endl;
        return;
    }
    
    // HexPrint(Aeskey.c_str(),Aeskey.length());

    // 使用AES秘钥 解密 device_info
    unsigned char decryptedtext[512]; 
    unsigned char aes_key[AES_KEY_SIZE];

    unsigned char ciphertext[512] = {0};

    memcpy(ciphertext, device_info.c_str(), device_info.length());
    memcpy(aes_key, Aeskey.c_str(), AES_KEY_SIZE);

    aes_decrypt(ciphertext, (const unsigned char *)aes_key, decryptedtext, device_info.length());

    // printf("decryptedtext_len:%d\n",strlen((char*)decryptedtext));
    // printf("device_info:%s\n",decryptedtext);


    unsigned char result[MD5_DIGEST_LENGTH];

    calculate_md5((char*)decryptedtext, result);

    char *json_string = License_Json_set(CUSTOMER_NAME, AUTHOR_NAME, project_name, result, days);

    // 将 MD5 值转换为十六进制字符串
    char esn_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex_string(result, esn_hex);
    
    char lic_file_path[64] = {0};
    sprintf(lic_file_path,"%s.lic", esn_hex);

    RSA *rsa_json = nullptr;
    std::string encrypted_json;
    //加密数据
    rsa_json = load_private_key(private_key_path);  // 加载私钥
    if (!rsa_json) {
        std::cerr << "Failed to load private key." << std::endl;
        return;
    }
    std::string json_string_str = json_string;

    // std::cout << json_string_str << std::endl;
    // 采用的RSA-2048加密，JSON字符串不能超过256字节，否则会报错

    encrypted_json = encrypt_with_private_key(rsa_json, json_string_str);  // 使用私钥加密
    if (encrypted_json.empty()) {
        std::cerr << "Failed to encrypt license." << std::endl;
        return;
    }
    
    //储存到license文件
    std::string encoded_json = base64_encode(encrypted_json);
    std::ofstream ofs(lic_file_path);
    if (!ofs) {
        std::cerr << "Failed to open license file for writing." << std::endl;
        return;
    }
    ofs << encoded_json;
    ofs.close();

    std::cout << "license file: " << lic_file_path <<std::endl;


    // 释放 JSON 字符串
    free(json_string);

}

// 解密并显示授权信息
void display_license(const char *device_did, const char *private_key_path) {
    printf("Displaying license information for device: %s\n", device_did);
    std::ifstream ifs(device_did);
    if (!ifs) {
        std::cerr << "Failed to open device.did file for reading." << std::endl;
        return;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string encoded = buffer.str();
    ifs.close();

    std::string encrypted = base64_decode(encoded);

    if(encrypted.length() <= (RSA_KEY_SIZE + sizeof(int)))
    {
        std::cerr << "Invalid device.did file." << std::endl;
        return;
    }
    // 提取被 RSA 加密的 aeskey
    std::string aeskey = encrypted.substr(0, RSA_KEY_SIZE);

    // HexPrint(aeskey.c_str(),aeskey.length());

    // 提取被 AES 加密的 device_info
    std::string device_info = encrypted.substr(RSA_KEY_SIZE + sizeof(int));

    // HexPrint(device_info.c_str(),device_info.length());

    //解密获得AES秘钥
    RSA *rsa = nullptr;
    rsa = load_private_key(private_key_path);  // 加载私钥
    if (!rsa) {
        std::cerr << "Failed to load private key." << std::endl;
        return;
    }
    std::string Aeskey = decrypt_with_private_key(rsa, aeskey);  // 使用私钥解密
    if (Aeskey.empty()) {
        std::cerr << "Failed to get Aeskey." << std::endl;
        return;
    }
    
    // HexPrint(Aeskey.c_str(),Aeskey.length());

    // 使用AES秘钥 解密 device_info
    unsigned char decryptedtext[512]; 
    unsigned char aes_key[AES_KEY_SIZE];

    unsigned char ciphertext[512] = {0};

    memcpy(ciphertext, device_info.c_str(), device_info.length());
    memcpy(aes_key, Aeskey.c_str(), AES_KEY_SIZE);

    aes_decrypt(ciphertext, (const unsigned char *)aes_key, decryptedtext, device_info.length());

    // printf("decryptedtext_len:%d\n",strlen((char*)decryptedtext));
    printf("device_info:%s\n",decryptedtext);


    unsigned char result[MD5_DIGEST_LENGTH];

    calculate_md5((char*)decryptedtext, result);


    // 将 MD5 值转换为十六进制字符串
    char esn_hex[MD5_DIGEST_LENGTH * 2 + 1];
    md5_to_hex_string(result, esn_hex);
    printf("MD5:%s\n",esn_hex);

}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [options]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  new <public_key.pem> <private_key.pem>   Generate a new key pair\n");
        fprintf(stderr, "  create <device.did> [-t days] [-p project_name] [-k private_key_path]   Create a license file\n");
        fprintf(stderr, "  display <device.did> [-k private_key_path] Decrypt and display license information\n");
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "new") == 0) {
        // 生成秘钥对
        if (argc != 4) {
            fprintf(stderr, "Usage: %s new <public_key.pem> <private_key.pem>\n", argv[0]);
            return 1;
        }
        std::string pub_key_file = argv[2];
        std::string pri_key_file = argv[3];
        if (generate_rsa_keypair(pub_key_file, pri_key_file)) {
            std::cout << "RSA key pair generated successfully." << std::endl;
        } else {
            std::cerr << "Failed to generate RSA key pair." << std::endl;
        }
    } else if (strcmp(command, "create") == 0) {
        // 创建授权文件
        if (argc < 3) {
            fprintf(stderr, "Usage: %s create <device.did> [-t days] [-p project_name] [-k private_key_path]\n", argv[0]);
            return 1;
        }
        const char *device_did = argv[2];
        int days = DEFAULT_TIME; // 默认值
        const char *project_name = PROJECT_NAME;
        const char *private_key_path = RSA_PRIKEY_FILE;

        // 使用 getopt 解析可选参数
        int opt;
        while ((opt = getopt(argc, argv, "t:p:k:")) != -1) {
            switch (opt) {
                case 't':
                    days = atoi(optarg);
                    break;
                case 'p':
                    project_name = optarg;
                    break;
                case 'k':
                    private_key_path = optarg;
                    break;
                default:
                    fprintf(stderr, "Usage: %s create <device.did> [-t days] [-p project_name] [-k private_key_path]\n", argv[0]);
                    return 1;
            }
        }
        create_license(device_did, days, project_name, private_key_path);
    } else if (strcmp(command, "display") == 0) {
        // 解密并显示授权信息
        if (argc < 3) {
            fprintf(stderr, "Usage: %s display <device.did> [-k private_key_path]\n", argv[0]);
            return 1;
        }

        const char *device_did = argv[2];
        const char *private_key_path = RSA_PRIKEY_FILE;

        int opt;
        while ((opt = getopt(argc, argv, "k:")) != -1) {
            switch (opt) {
                case 'k':
                    private_key_path = optarg;
                    break;
                default:
                    fprintf(stderr, "Usage: %s display <device.did> [-k private_key_path]\n", argv[0]);
                    return 1;
            }
        }
        display_license(device_did,private_key_path);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}