#include "password_checkup.h"
#include <iostream>
#include <stdexcept>

const char* SERVER_IP = "127.0.0.1";
const int PORT = 12345;

// 客户端秘密分割（论文Figure 2步骤1-3）
std::pair<std::vector<uchar>, std::vector<uchar>> split_secret(const std::vector<uchar>& h_pw) {
    // 生成随机数r（与哈希同长度）
    std::vector<uchar> r = generate_random_bytes(h_pw.size());
    
    // 计算s = h_pw XOR r（论文中的秘密分割）
    std::vector<uchar> s(h_pw.size());
    for (size_t i = 0; i < h_pw.size(); ++i) {
        s[i] = h_pw[i] ^ r[i];
    }
    
    return {r, s};
}

int main() {
    #pragma warning(disable: 4996)
    
    // 初始化Winsock
    if (!init_winsock()) {
        std::cerr << "Winsock初始化失败: " << WSAGetLastError() << std::endl;
        return 1;
    }

    SOCKET client_socket = INVALID_SOCKET;
    try {
        // 1. 客户端输入密码并计算哈希（h_pw = H(pw)）
        std::string password = get_password("请输入要检查的密码: ");
        std::vector<uchar> h_pw = hash_password(password);
        password.clear();  // 立即清除明文密码
        std::cout << "已计算密码哈希，开始隐私保护检查..." << std::endl;

        // 2. 秘密分割：生成r和s = h_pw XOR r（论文核心步骤）
        auto [r, s] = split_secret(h_pw);
        h_pw.clear();  // 清除哈希值，不再需要

        // 3. 创建并连接服务器
        client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client_socket == INVALID_SOCKET) {
            throw std::runtime_error("创建套接字失败: " + std::to_string(WSAGetLastError()));
        }

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
            throw std::runtime_error("无效的服务器IP地址");
        }
        server_addr.sin_port = htons(PORT);

        if (connect(client_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            throw std::runtime_error("连接服务器失败: 请确保服务器已启动");
        }

        // 4. 发送s给服务器（论文Figure 2步骤4）
        if (!send_length_prefix_data(client_socket, s.data(), s.size())) {
            throw std::runtime_error("发送秘密份额失败");
        }
        s.clear();  // 清除s，不再需要
        std::cout << "已发送秘密份额，等待服务器响应..." << std::endl;

        // 5. 接收服务器返回的t'（论文Figure 2步骤5）
        std::vector<uchar> t_prime = receive_length_prefix_data(client_socket);
        if (t_prime.empty() || t_prime.size() != r.size()) {
            throw std::runtime_error("接收无效的服务器响应");
        }

        // 6. 计算t = t' XOR r并检查是否为0（论文Figure 2步骤6-7）
        bool is_leaked = false;
        for (size_t i = 0; i < t_prime.size(); ++i) {
            if ((t_prime[i] ^ r[i]) == 0) {
                is_leaked = true;
                break;
            }
        }

        // 7. 输出结果
        std::cout << "检查结果: " << (is_leaked ? 
            "密码已泄露！" : "密码安全（未在泄露列表中）") << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "客户端错误: " << e.what() << std::endl;
    }

    // 清理资源
    if (client_socket != INVALID_SOCKET) {
        closesocket(client_socket);
    }
    cleanup_winsock();
    
    std::cout << "按任意键退出..." << std::endl;
    std::cin.get();
    
    return 0;
}
