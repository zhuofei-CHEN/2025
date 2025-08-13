#include "password_checkup.h"
#include <iostream>

int main() {
    try {
        // 示例泄露密码列表
        std::vector<std::string> common_passwords = {
            "password123",
            "123456",
            "qwerty",
            "abc123",
            "letmein",
            "monkey",
            "123456789",
            "111111",
            "password",
            "sunshine",
            "iloveyou",
            "princess",
            "admin",
            "welcome",
            "666666",
            "123123",
            "dragon",
            "passw0rd",
            "master",
            "football"
        };
        
        // 创建泄露密码文件
        std::ofstream file("leaked_passwords.txt");
        if (!file.is_open()) {
            throw std::runtime_error("无法创建泄露密码文件: leaked_passwords.txt");
        }
        
        // 为每个密码生成哈希并写入文件（格式：哈希:盐值，盐值仅用于演示）
        for (const std::string& pw : common_passwords) {
            std::vector<uchar> hash = hash_password(pw);
            std::vector<uchar> salt = generate_random_bytes(16); // 16字节盐值
            
            std::string hash_hex = bytes_to_hex(hash.data(), hash.size());
            std::string salt_hex = bytes_to_hex(salt.data(), salt.size());
            
            file << hash_hex << ":" << salt_hex << std::endl;
        }
        
        file.close();
        std::cout << "成功生成泄露密码文件: leaked_passwords.txt" << std::endl;
        std::cout << "包含 " << common_passwords.size() << " 个常见泄露密码" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    
    // 等待用户按键再退出
    std::cout << "按任意键退出..." << std::endl;
    std::cin.get();
    
    return 0;
}
