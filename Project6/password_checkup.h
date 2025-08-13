#ifndef PASSWORD_CHECKUP_H
#define PASSWORD_CHECKUP_H

#include <vector>
#include <string>
#include <cstdint>
#include <winsock2.h>
#include <openssl/sha.h>

// 类型定义
using uchar = unsigned char;

// Winsock相关函数
bool init_winsock();
void cleanup_winsock();

// 密码哈希函数
std::vector<uchar> hash_password(const std::string& password);

// 字节与十六进制转换
std::string bytes_to_hex(const uchar* bytes, size_t length);
std::vector<uchar> hex_to_bytes(const std::string& hex);

// 密码输入函数
std::string get_password(const std::string& prompt);

// 数据传输函数
bool send_length_prefix_data(SOCKET socket, const uchar* data, size_t length);
std::vector<uchar> receive_length_prefix_data(SOCKET socket);

// 随机数生成
std::vector<uchar> generate_random_bytes(size_t length);

#endif // PASSWORD_CHECKUP_H
