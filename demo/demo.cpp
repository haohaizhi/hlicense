#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

#define RSA_KEY_LENGTH 2048
#define PUB_EXPONENT 65537

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
// 使用公钥加密数据
std::string encrypt_with_public_key(RSA *rsa, const std::string &message) {
    if (!rsa) {
        std::cerr << "Invalid RSA key." << std::endl;
        return "";
    }

    // 设置加密缓冲区大小
    int rsa_len = RSA_size(rsa);  // 获取RSA加密块的大小
    unsigned char *encrypted = new unsigned char[rsa_len];

    // 使用公钥加密数据
    int result_len = RSA_public_encrypt(message.size(), 
                                        reinterpret_cast<const unsigned char *>(message.c_str()),
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
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [-n pub_key_file pri_key_file] [-e {-pk private_key.pem|-pu public_key.pem} message license_file] [-d {-du public_key.pem|-dk private_key.pem} license_file]" << std::endl;
        return 1;
    }

    std::string option = argv[1];

    if (option == "-n" && argc == 4) {
        std::string pub_key_file = argv[2];
        std::string pri_key_file = argv[3];
        if (generate_rsa_keypair(pub_key_file, pri_key_file)) {
            std::cout << "RSA key pair generated successfully." << std::endl;
        } else {
            std::cerr << "Failed to generate RSA key pair." << std::endl;
        }
    } else if (option == "-e" && argc == 6) {
    std::string key_option = argv[2];  // 密钥加密选项: -pk或者-pu
    std::string key_file = argv[3];  // 密钥文件路径
    std::string message = argv[4];  // 要加密的消息
    std::string license_file = argv[5];  // 保存的授权文件

    RSA *rsa = nullptr;
    std::string encrypted;

    // 选择加密方式
    if (key_option == "-pk") {
        rsa = load_private_key(key_file);  // 加载私钥
        if (!rsa) {
            std::cerr << "Failed to load private key." << std::endl;
            return 1;
        }
        encrypted = encrypt_with_private_key(rsa, message);  // 使用私钥加密
        if (encrypted.empty()) {
            std::cerr << "Failed to encrypt message." << std::endl;
            return 1;
        }
    } else if (key_option == "-pu") {
        rsa = load_public_key(key_file);  // 加载公钥
        if (!rsa) {
            std::cerr << "Failed to load public key." << std::endl;
            return 1;
        }
        encrypted = encrypt_with_public_key(rsa, message);  // 使用公钥加密
        if (encrypted.empty()) {
            std::cerr << "Failed to encrypt message." << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Invalid encryption option. Use -pk or -pu." << std::endl;
        return 1;
    }

    // 编码为 Base64 并保存到授权文件
    std::string encoded = base64_encode(encrypted);
    std::ofstream ofs(license_file);
    if (!ofs) {
        std::cerr << "Failed to open license file for writing." << std::endl;
        return 1;
    }
    ofs << encoded;
    ofs.close();

    std::cout << "Message encrypted and saved to license file." << std::endl;
    } else if (option == "-d" && argc == 5) {
    std::string key_option = argv[2];  // 密钥解密选项: -dk 或 -du
    std::string key_file = argv[3];  // 密钥文件路径
    std::string license_file = argv[4];  // 授权文件路径

    RSA *rsa = nullptr;

    // 读取授权文件中的 Base64 编码字符串
    std::ifstream ifs(license_file);
    if (!ifs) {
        std::cerr << "Failed to open license file for reading." << std::endl;
        return 1;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string encoded = buffer.str();
    ifs.close();

    std::string encrypted = base64_decode(encoded);

    // 选择解密方式
    if (key_option == "-dk") {
        rsa = load_private_key(key_file);  // 加载私钥
        if (!rsa) {
            std::cerr << "Failed to load private key." << std::endl;
            return 1;
        }
        std::string decrypted = decrypt_with_private_key(rsa, encrypted);  // 使用私钥解密
        if (decrypted.empty()) {
            std::cerr << "Failed to decrypt message." << std::endl;
            return 1;
        }
        std::cout << "Decrypted message: " << decrypted << std::endl;
      } else if (key_option == "-du") {
        rsa = load_public_key(key_file);  // 加载公钥
        if (!rsa) {
            std::cerr << "Failed to load public key." << std::endl;
            return 1;
        }
        std::string decrypted = decrypt_with_public_key(rsa, encrypted);  // 使用公钥解密
        if (decrypted.empty()) {
            std::cerr << "Failed to decrypt message." << std::endl;
            return 1;
        }
        std::cout << "Decrypted message: " << decrypted << std::endl;
     } else {
        std::cerr << "Invalid decryption option. Use -dk or -du." << std::endl;
        return 1;
     }
    } else {
        std::cerr << "Invalid arguments." << std::endl;
        return 1;
    }

    return 0;
}

