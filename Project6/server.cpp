#include "password_checkup.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <signal.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")

const int PORT = 12345;

// 全局变量
std::vector<std::vector<uchar>> leaked_hashes;
std::mutex console_mutex;
std::atomic<bool> server_running(true);

// 信号处理函数（处理Ctrl+C退出）
void handle_signal(int signal) {
    if (signal == SIGINT) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << "\n收到退出信号，正在关闭服务器..." << std::endl;
        server_running = false;
    }
}

// 加载泄露的密码哈希库
bool load_leaked_hashes(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    size_t line_num = 0;
    while (std::getline(file, line)) {
        line_num++;
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "警告: 跳过格式错误的行 " << line_num << std::endl;
            continue;
        }
        
        std::string hash_hex = line.substr(0, colon_pos);
        try {
            std::vector<uchar> hash = hex_to_bytes(hash_hex);
            if (hash.size() == SHA256_DIGEST_LENGTH) {
                leaked_hashes.push_back(hash);
            } else {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "警告: 跳过长度错误的哈希（行 " << line_num << "）" << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "警告: 跳过无效的哈希（行 " << line_num << "）: " << e.what() << std::endl;
        }
    }
    
    file.close();
    return !leaked_hashes.empty();
}

// 处理客户端连接（论文Figure 2服务器端逻辑）
void handle_client(SOCKET client_socket, const std::string& client_ip) {
    {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << "新客户端连接: " << client_ip << std::endl;
    }

    try {
        // 1. 接收客户端发送的s（论文步骤4）
        std::vector<uchar> s = receive_length_prefix_data(client_socket);
        if (s.empty() || s.size() != SHA256_DIGEST_LENGTH) {
            throw std::runtime_error("接收无效的秘密份额s");
        }

        // 2. 计算t'_i = s XOR h_pw'_i 并累积XOR结果（论文步骤5-6）
        std::vector<uchar> t_prime(SHA256_DIGEST_LENGTH, 0);
        bool first = true;

        for (const auto& h_pw_prime : leaked_hashes) {
            std::vector<uchar> t_i(SHA256_DIGEST_LENGTH);
            
            // 计算t'_i = s XOR h_pw'_i
            for (size_t j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
                t_i[j] = s[j] ^ h_pw_prime[j];
            }
            
            // 累积XOR: t' = t'_1 XOR t'_2 XOR ... XOR t'_n
            if (first) {
                t_prime = t_i;
                first = false;
            } else {
                for (size_t j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
                    t_prime[j] ^= t_i[j];
                }
            }
        }

        // 3. 发送t'给客户端（论文步骤5）
        if (!send_length_prefix_data(client_socket, t_prime.data(), t_prime.size())) {
            throw std::runtime_error("发送t'失败");
        }

        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "客户端 " << client_ip << " 处理完成" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "客户端 " << client_ip << " 处理错误: " << e.what() << std::endl;
    }

    // 清理
    closesocket(client_socket);
}

int main() {
    // 禁用安全警告
    #pragma warning(disable: 4996)
    
    // 设置信号处理
    signal(SIGINT, handle_signal);
    
    // 初始化Winsock
    if (!init_winsock()) {
        std::cerr << "Winsock初始化失败: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // 加载泄露密码哈希库
    if (!load_leaked_hashes("leaked_passwords.txt")) {
        std::cerr << "无法加载泄露密码文件: leaked_passwords.txt" << std::endl;
        cleanup_winsock();
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << "已加载 " << leaked_hashes.size() << " 个泄露密码哈希" << std::endl;
    }

    // 创建服务器套接字
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        std::cerr << "创建套接字失败: " << WSAGetLastError() << std::endl;
        cleanup_winsock();
        return 1;
    }

    // 设置套接字选项（允许地址重用）
    int optval = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
                  reinterpret_cast<const char*>(&optval), sizeof(optval)) == SOCKET_ERROR) {
        std::cerr << "设置套接字选项失败: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        cleanup_winsock();
        return 1;
    }

    // 绑定地址和端口
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "绑定失败: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        cleanup_winsock();
        return 1;
    }

    // 监听连接
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "监听失败: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        cleanup_winsock();
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << "服务器启动成功，监听端口 " << PORT << " ..." << std::endl;
        std::cout << "按Ctrl+C停止服务器" << std::endl;
    }

    // 存储所有客户端线程
    std::vector<std::thread> client_threads;

    // 处理客户端连接
    while (server_running) {
        // 使用select实现非阻塞等待，允许响应退出信号
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        
        timeval timeout;
        timeout.tv_sec = 1;  // 1秒超时
        timeout.tv_usec = 0;
        
        int result = select(0, &read_fds, nullptr, nullptr, &timeout);
        if (result == SOCKET_ERROR) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "select错误: " << WSAGetLastError() << std::endl;
            continue;
        }
        else if (result == 0) {
            // 超时，检查是否需要退出
            continue;
        }

        // 有连接到来
        sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(server_socket, (SOCKADDR*)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "接受连接失败: " << WSAGetLastError() << std::endl;
            continue;
        }

        // 获取客户端IP地址
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        // 启动新线程处理客户端
        client_threads.emplace_back(handle_client, client_socket, std::string(client_ip));
        // 分离线程，让其自动清理
        client_threads.back().detach();
        // 清理已完成的线程
        client_threads.erase(
            std::remove_if(client_threads.begin(), client_threads.end(),
                         [](std::thread& t) { return !t.joinable(); }),
            client_threads.end()
        );
    }

    // 清理
    closesocket(server_socket);
    cleanup_winsock();
    
    std::cout << "服务器已关闭" << std::endl;
    return 0;
}
