1、安装编译环境
sudo apt-get install libssl-dev

2、编译程序
g++ -o demo demo.cpp -lssl -lcrypto


3、验证
# 生成密钥对
./demo -n public_key.pem private_key.pem

# 私钥加密，公钥解密：
./demo -e -pk private_key.pem "hello,world" license_file.txt
./demo -d -du public_key.pem license_file.txt

# 使用公钥解密
./demo -e -pu public_key.pem "hello,world" license_file.txt
./demo -d -dk private_key.pem license_file.txt