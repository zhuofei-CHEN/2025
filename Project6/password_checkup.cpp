#include "password_checkup.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <conio.h>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

// Winsock初始化
bool init_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    return result == 0;
}

// Winsock清理
void cleanup_winsock() {
    WSACleanup();
}

// 计算密码哈希（论文中的H(·)，使用SHA-256）
std::vector<uchar> hash_password(const std::string& password) {
    std::vector<uchar> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uchar*>(password.c_str()), password.size(), hash.data());
    return hash;
}

// 字节转换为十六进制字符串
std::string bytes_to_hex(const uchar* bytes, size_t length) {
    if (!bytes || length == 0) return "";
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

// 十六进制字符串转换为字节
std::vector<uchar> hex_to_bytes(const std::string& hex) {
    std::vector<uchar> bytes;
    
    if (hex.empty() || hex.length() % 2 != 0) {
        throw std::invalid_argument("无效的十六进制字符串");
    }
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        char* endptr;
        unsigned long val = strtoul(byte_str.c_str(), &endptr, 16);
        
        if (endptr != byte_str.c_str() + 2) {
            throw std::invalid_argument("无效的十六进制字符: " + byte_str);
        }
        
        bytes.push_back(static_cast<uchar>(val));
    }
    
    return bytes;
}

// 获取密码输入（隐藏显示）
std::string get_password(const std::string& prompt) {
    std::cout << prompt;
    
    // 保存控制台模式
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("无法获取控制台句柄");
    }
    
    DWORD mode;
    if (!GetConsoleMode(hConsole, &mode)) {
        throw std::runtime_error("无法获取控制台模式");
    }
    
    // 禁用回显
    DWORD new_mode = mode & ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(hConsole, new_mode)) {
        throw std::runtime_error("无法设置控制台模式");
    }
    
    std::string password;
    char ch;
    
    try {
        while ((ch = _getch()) != '\r') {  // 直到按下回车键
            if (ch == '\b') {  // 处理退格键
                if (!password.empty()) {
                    password.pop_back();
                    std::cout << "\b \b";  // 清除屏幕上的字符
                }
            } else if (ch >= 32 && ch <= 126) {  // 只接受可打印字符
                password += ch;
                std::cout << '*';  // 显示星号代替实际字符
            }
        }
        std::cout << std::endl;
    }
    catch (...) {
        // 确保恢复控制台模式
        SetConsoleMode(hConsole, mode);
        throw;
    }
    
    // 恢复控制台模式
    SetConsoleMode(hConsole, mode);
    return password;
}

// 带长度前缀的数据发送
bool send_length_prefix_data(SOCKET socket, const uchar* data, size_t length) {
    if (socket == INVALID_SOCKET || !data || length == 0) {
        return false;
    }
    
    // 发送长度（4字节，网络字节序）
    uint32_t len = htonl(static_cast<uint32_t>(length));
    int result = send(socket, reinterpret_cast<const char*>(&len), 4, 0);
    if (result != 4) {
        return false;
    }
    
    // 发送数据
    size_t total_sent = 0;
    while (total_sent < length) {
        result = send(socket, reinterpret_cast<const char*>(data + total_sent), 
                       static_cast<int>(length - total_sent), 0);
        if (result <= 0) {
            return false;
        }
        total_sent += static_cast<size_t>(result);
    }
    
    return true;
}

// 带长度前缀的数据接收
std::vector<uchar> receive_length_prefix_data(SOCKET socket) {
    if (socket == INVALID_SOCKET) {
        return {};
    }
    
    // 接收长度
    uint32_t len;
    int result = recv(socket, reinterpret_cast<char*>(&len), 4, 0);
    if (result != 4) {
        return {};
    }
    len = ntohl(len);
    
    // 验证长度合理性（防止内存分配攻击）
    if (len == 0 || len > 1024 * 1024) {  // 限制最大1MB
        return {};
    }
    
    // 接收数据
    std::vector<uchar> data(len);
    size_t total_received = 0;
    
    while (total_received < len) {
        result = recv(socket, reinterpret_cast<char*>(data.data() + total_received), 
                          static_cast<int>(len - total_received), 0);
        if (result <= 0) {
            return {};
        }
        total_received += static_cast<size_t>(result);
    }
    
    return data;
}

// 生成密码学安全的随机数
std::vector<uchar> generate_random_bytes(size_t length) {
    if (length == 0) {
        return {};
    }
    
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw std::runtime_error("无法获取加密上下文: " + std::to_string(GetLastError()));
    }
    
    std::vector<uchar> random_bytes(length);
    bool success = CryptGenRandom(hProv, static_cast<DWORD>(length), random_bytes.data());
    CryptReleaseContext(hProv, 0);  // 确保释放资源
    
    if (!success) {
        throw std::runtime_error("随机数生成失败: " + std::to_string(GetLastError()));
    }
    
    return random_bytes;
}
