#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <immintrin.h>
#include <numeric>
#include <cstring>
#include <memory>
#include <stdexcept>  // 用于异常处理

using namespace std;
using namespace chrono;

// SM3核心常量与标量函数（遵循GM/T 0004-2012标准）
// 初始哈希值H0
const uint32_t SM3_H0[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 常量Tj（前16个为0x79CC4519，后48个为0x7A879D8A）
const uint32_t SM3_T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// 哈希结果长度（32字节）和块大小（64字节）
#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

// 标量辅助函数
// 32位循环左移
static inline uint32_t rotl32(uint32_t x, int n) {
    n %= 32;  // 确保移位量在0-31之间
    return (x << n) | (x >> (32 - n));
}

// 置换函数P0
static inline uint32_t P0(uint32_t x) {
    return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

// 置换函数P1
static inline uint32_t P1(uint32_t x) {
    return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

// 压缩函数中的布尔函数FF
static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;  // 前16轮
    else return (x & y) | (x & z) | (y & z);  // 后48轮
}

// 压缩函数中的布尔函数GG
static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;  // 前16轮
    else return (x & y) | (~x & z);  // 后48轮
}

// SIMD辅助函数（AVX2指令集支持，8个32位整数并行处理）
// 256位向量的循环左移（每个32位元素独立左移）
static inline __m256i rotl256_32(__m256i x, int n) {
    const __m256i mask = _mm256_set1_epi32(0xFFFFFFFF >> (32 - n));  // 掩码用于清除移位产生的无效位
    __m256i lo = _mm256_slli_epi32(x, n);  // 左移
    __m256i hi = _mm256_and_si256(_mm256_srli_epi32(x, 32 - n), mask);  // 右移并掩码
    return _mm256_or_si256(lo, hi);  // 合并结果
}

// 向量版置换函数P0
static inline __m256i P0_256(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl256_32(x, 9)), rotl256_32(x, 17));
}

// 向量版置换函数P1
static inline __m256i P1_256(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl256_32(x, 15)), rotl256_32(x, 23));
}

// 向量版布尔函数FF（前16轮）
static inline __m256i FF0_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

// 向量版布尔函数FF（后48轮）
static inline __m256i FF1_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(x, z)), _mm256_and_si256(y, z));
}

// 向量版布尔函数GG（前16轮）
static inline __m256i GG0_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

// 向量版布尔函数GG（后48轮）
static inline __m256i GG1_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_or_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z));
}

// 字节序转换掩码（将小端存储的4字节整数转换为大端）
alignas(32) const uint8_t swap_mask_data[32] = {
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
    19,18,17,16, 23,22,21,20, 27,26,25,24, 31,30,29,28
};
const __m256i swap_mask = _mm256_loadu_si256((const __m256i*)swap_mask_data);

// SM3上下文结构（用于哈希计算过程中的状态保存）
struct SM3Context {
    uint32_t state[8];      // 当前哈希状态
    uint64_t length;        // 消息总长度（比特）
    uint8_t buffer[SM3_BLOCK_SIZE];  // 消息块缓冲区
    int ptr;                // 缓冲区当前位置
};

// 初始化SM3上下文
void sm3_init(SM3Context* ctx) {
    if (!ctx) return;
    memcpy(ctx->state, SM3_H0, sizeof(SM3_H0));  // 初始化为H0
    ctx->length = 0;
    ctx->ptr = 0;
}

// 标量压缩函数（处理单个512比特消息块）
void sm3_compress_basic(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68] = { 0 };   // 消息扩展字W0-W67
    uint32_t W1[64] = { 0 };  // 消息扩展字W'0-W'63
    uint32_t A, B, C, D, E, F, G, H;  // 压缩过程中的中间变量
    int j;

    // 消息扩展：计算W0-W15（从消息块转换）
    for (j = 0; j < 16; j++) {
        W[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) |
            (block[j * 4 + 2] << 8) | block[j * 4 + 3];
    }

    // 消息扩展：计算W16-W67
    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15)) ^
            rotl32(W[j - 13], 7) ^ W[j - 6];
    }

    // 消息扩展：计算W'0-W'63
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 初始化压缩变量
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    // 64轮压缩
    for (j = 0; j < 64; j++) {
        uint32_t SS1 = rotl32(rotl32(A, 12) + E + rotl32(SM3_T[j], j), 7);
        uint32_t SS2 = SS1 ^ rotl32(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        // 更新压缩变量
        D = C;
        C = rotl32(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = rotl32(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 更新哈希状态
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// SIMD压缩函数（使用AVX2指令集并行处理，加速压缩过程）
void sm3_compress_simd(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE]) {
    // 动态分配32字节对齐的内存（避免栈溢出，替代原栈上数组）
    alignas(32) uint32_t* W = static_cast<uint32_t*>(_aligned_malloc(68 * sizeof(uint32_t), 32));
    alignas(32) uint32_t* W1 = static_cast<uint32_t*>(_aligned_malloc(64 * sizeof(uint32_t), 32));
    if (!W || !W1) {
        throw bad_alloc();  // 内存分配失败时抛出异常
    }
    memset(W, 0, 68 * sizeof(uint32_t));
    memset(W1, 0, 64 * sizeof(uint32_t));

    // 消息扩展：计算W0-W15（修复字节序，小端→大端）
    __m256i block_vec = _mm256_loadu_si256((const __m256i*)block);  // 加载前32字节
    block_vec = _mm256_shuffle_epi8(block_vec, swap_mask);  // 字节序转换
    _mm256_store_si256((__m256i*) & W[0], block_vec);  // 存储W0-W7

    block_vec = _mm256_loadu_si256((const __m256i*) & block[32]);  // 加载后32字节
    block_vec = _mm256_shuffle_epi8(block_vec, swap_mask);  // 字节序转换
    _mm256_store_si256((__m256i*) & W[8], block_vec);  // 存储W8-W15

    // 消息扩展：计算W16-W63（8组并行处理，避免越界）
    for (int i = 16; i <= 60; i += 8) {
        __m256i w_16 = _mm256_load_si256((__m256i*) & W[i - 16]);  // W[i-16..i-9]
        __m256i w_9 = _mm256_load_si256((__m256i*) & W[i - 9]);    // W[i-9..i-2]
        __m256i w_3 = _mm256_load_si256((__m256i*) & W[i - 3]);    // W[i-3..i+4]
        __m256i w_13 = _mm256_load_si256((__m256i*) & W[i - 13]);  // W[i-13..i-6]
        __m256i w_6 = _mm256_load_si256((__m256i*) & W[i - 6]);    // W[i-6..i+1]

        // 并行计算W[i..i+7]
        __m256i temp = _mm256_xor_si256(_mm256_xor_si256(w_16, w_9), rotl256_32(w_3, 15));
        temp = P1_256(temp);
        temp = _mm256_xor_si256(_mm256_xor_si256(temp, rotl256_32(w_13, 7)), w_6);

        _mm256_store_si256((__m256i*) & W[i], temp);
    }

    // 补全W64-W67（标量处理，避免越界）
    for (int j = 64; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15)) ^
            rotl32(W[j - 13], 7) ^ W[j - 6];
    }

    // 计算W1[0..63]（8组并行）
    for (int i = 0; i < 64; i += 8) {
        __m256i w = _mm256_load_si256((__m256i*) & W[i]);
        __m256i w4 = _mm256_load_si256((__m256i*) & W[i + 4]);
        _mm256_store_si256((__m256i*) & W1[i], _mm256_xor_si256(w, w4));  // W1[i] = W[i] ^ W[i+4]
    }

    // 初始化向量压缩变量（每个元素复制8次，实现并行处理）
    __m256i A = _mm256_set1_epi32(state[0]);
    __m256i B = _mm256_set1_epi32(state[1]);
    __m256i C = _mm256_set1_epi32(state[2]);
    __m256i D = _mm256_set1_epi32(state[3]);
    __m256i E = _mm256_set1_epi32(state[4]);
    __m256i F = _mm256_set1_epi32(state[5]);
    __m256i G = _mm256_set1_epi32(state[6]);
    __m256i H = _mm256_set1_epi32(state[7]);

    // 64轮压缩（8轮一组并行处理）
    alignas(32) uint32_t T_vec[8];  // 存储Tj的旋转结果
    for (int i = 0; i < 64; i += 8) {
        // 预计算当前8轮的Tj旋转结果
        for (int j = 0; j < 8; j++) {
            T_vec[j] = rotl32(SM3_T[i + j], i + j);
        }
        __m256i T_val = _mm256_load_si256((__m256i*)T_vec);
        __m256i Wi = _mm256_load_si256((__m256i*) & W[i]);
        __m256i W1i = _mm256_load_si256((__m256i*) & W1[i]);

        // 计算SS1和SS2
        __m256i rotA12 = rotl256_32(A, 12);
        __m256i SS1 = rotl256_32(_mm256_add_epi32(_mm256_add_epi32(rotA12, E), T_val), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, rotA12);

        // 计算TT1和TT2（分前16轮和后48轮）
        __m256i TT1, TT2;
        if (i < 16) {
            TT1 = _mm256_add_epi32(_mm256_add_epi32(FF0_256(A, B, C), D), _mm256_add_epi32(SS2, W1i));
            TT2 = _mm256_add_epi32(_mm256_add_epi32(GG0_256(E, F, G), H), _mm256_add_epi32(SS1, Wi));
        }
        else {
            TT1 = _mm256_add_epi32(_mm256_add_epi32(FF1_256(A, B, C), D), _mm256_add_epi32(SS2, W1i));
            TT2 = _mm256_add_epi32(_mm256_add_epi32(GG1_256(E, F, G), H), _mm256_add_epi32(SS1, Wi));
        }

        // 更新压缩变量
        D = C; C = rotl256_32(B, 9); B = A; A = TT1;
        H = G; G = rotl256_32(F, 19); F = E; E = P0_256(TT2);
    }

    // 更新哈希状态（合并8个并行结果）
    __m256i state_low = _mm256_load_si256((__m256i*)state);
    state_low = _mm256_xor_si256(state_low, A);
    _mm256_store_si256((__m256i*)state, state_low);

    __m256i state_high = _mm256_load_si256((__m256i*) & state[4]);
    state_high = _mm256_xor_si256(state_high, E);
    _mm256_store_si256((__m256i*) & state[4], state_high);

    // 释放堆内存（避免内存泄漏）
    _aligned_free(W);
    _aligned_free(W1);
}

// 更新SM3上下文（处理输入数据）
void sm3_update(SM3Context* ctx, const uint8_t* data, size_t len, bool use_simd = false) {
    if (!ctx || !data || len == 0) return;

    // 处理输入数据，填满缓冲区后调用压缩函数
    while (len > 0) {
        int copy = SM3_BLOCK_SIZE - ctx->ptr;  // 计算可复制的字节数
        if (copy > (int)len) copy = (int)len;
        memcpy(ctx->buffer + ctx->ptr, data, copy);  // 复制数据到缓冲区
        ctx->ptr += copy;
        data += copy;
        len -= copy;
        ctx->length += copy * 8;  // 更新总长度（比特）

        // 缓冲区满时进行压缩
        if (ctx->ptr == SM3_BLOCK_SIZE) {
            if (use_simd) sm3_compress_simd(ctx->state, ctx->buffer);
            else sm3_compress_basic(ctx->state, ctx->buffer);
            ctx->ptr = 0;  // 重置缓冲区
        }
    }
}

// 完成SM3哈希计算（处理填充和最终压缩）
void sm3_final(SM3Context* ctx, uint8_t digest[SM3_DIGEST_SIZE], bool use_simd = false) {
    if (!ctx || !digest) return;

    uint64_t final_length = ctx->length;
    int final_ptr = ctx->ptr;

    // 填充消息：添加0x80和若干0
    ctx->buffer[final_ptr++] = 0x80;
    if (final_ptr > 56) {  // 缓冲区剩余空间不足存储长度（8字节）
        memset(ctx->buffer + final_ptr, 0, SM3_BLOCK_SIZE - final_ptr);
        if (use_simd) sm3_compress_simd(ctx->state, ctx->buffer);
        else sm3_compress_basic(ctx->state, ctx->buffer);
        final_ptr = 0;
    }
    memset(ctx->buffer + final_ptr, 0, 56 - final_ptr);  // 填充0至56字节

    // 附加消息总长度（64比特，大端存储）
    uint64_t len_bits = final_length;
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (len_bits >> (8 * (7 - i))) & 0xFF;
    }

    // 最后一次压缩
    if (use_simd) sm3_compress_simd(ctx->state, ctx->buffer);
    else sm3_compress_basic(ctx->state, ctx->buffer);

    // 输出哈希结果（大端字节序）
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

// 计算SM3哈希（便捷函数）
void sm3_hash(const uint8_t* data, size_t len, uint8_t digest[SM3_DIGEST_SIZE], bool use_simd = false) {
    SM3Context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len, use_simd);
    sm3_final(&ctx, digest, use_simd);
}

// 从哈希值恢复状态（用于长度扩展攻击）
void sm3_recover_state(const uint8_t* hash, uint32_t state[8]) {
    if (!hash || !state) return;
    for (int i = 0; i < 8; i++) {
        state[i] = (hash[i * 4] << 24) | (hash[i * 4 + 1] << 16) |
            (hash[i * 4 + 2] << 8) | hash[i * 4 + 3];
    }
}

// 计算填充长度（用于长度扩展攻击）
size_t sm3_calculate_pad_length(size_t original_len) {
    size_t total_required = original_len + 1 + 8;  // 数据+0x80+长度(8字节)
    size_t remainder = total_required % SM3_BLOCK_SIZE;
    return remainder == 0 ? 0 : SM3_BLOCK_SIZE - remainder;
}

// 长度扩展攻击实现
void sm3_length_extension_attack(
    const uint8_t* original_hash,
    size_t original_len,
    const uint8_t* extension,
    size_t ext_len,
    uint8_t result_hash[SM3_DIGEST_SIZE],
    bool use_simd = false
) {
    if (!original_hash || !extension || !result_hash) return;

    SM3Context ctx;
    sm3_init(&ctx);
    sm3_recover_state(original_hash, ctx.state);  // 从原始哈希恢复状态

    // 计算填充长度并设置总长度（原始数据+填充的总长度）
    size_t pad_len = 1 + sm3_calculate_pad_length(original_len) + 8;
    ctx.length = (original_len + pad_len) * 8;

    // 处理扩展数据
    sm3_update(&ctx, extension, ext_len, use_simd);
    sm3_final(&ctx, result_hash, use_simd);
}

// 哈希值转为字符串（16进制）
string hash_to_string(const uint8_t* digest) {
    if (!digest) return "";
    stringstream ss;
    ss << hex << setfill('0');  // 填充0以保证2位16进制数
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        ss << setw(2) << (int)digest[i];  // 每个字节转为2位16进制
    }
    return ss.str();
}

// 字符串转为哈希值（16进制字符串→字节数组）
bool string_to_hash(const string& hash_str, uint8_t* digest) {
    if (hash_str.length() != 2 * SM3_DIGEST_SIZE || !digest) return false;

    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        string byte_str = hash_str.substr(i * 2, 2);  // 提取2个字符（1个字节）
        digest[i] = (uint8_t)stoul(byte_str, nullptr, 16);  // 转为字节
    }
    return true;
}

// 便捷的字符串哈希函数
string sm3_hash_string(const string& data, bool use_simd = false) {
    uint8_t digest[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t*)data.c_str(), data.size(), digest, use_simd);
    return hash_to_string(digest);
}

// 验证长度扩展攻击
bool verify_length_extension() {
    const string msg = "secret message";
    const string ext = "extended data";

    // 计算原始消息哈希
    uint8_t original_hash[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t*)msg.c_str(), msg.size(), original_hash, false);
    cout << "原始消息哈希: " << hash_to_string(original_hash) << endl;

    // 构造真实的扩展消息（原始消息 + 填充 + 扩展数据）
    size_t pad_len = sm3_calculate_pad_length(msg.size());
    size_t total_len = msg.size() + 1 + pad_len + 8 + ext.size();
    vector<uint8_t> forged_msg(total_len);

    // 复制原始消息
    memcpy(forged_msg.data(), msg.c_str(), msg.size());
    size_t ptr = msg.size();

    // 添加填充
    forged_msg[ptr++] = 0x80;
    if (pad_len > 0) {
        memset(forged_msg.data() + ptr, 0, pad_len);
        ptr += pad_len;
    }

    // 添加长度（64比特）
    uint64_t len_bits = (uint64_t)msg.size() * 8;
    for (int i = 0; i < 8; i++) {
        forged_msg[ptr++] = (len_bits >> (8 * (7 - i))) & 0xFF;
    }

    // 添加扩展数据
    memcpy(forged_msg.data() + ptr, ext.c_str(), ext.size());

    // 计算真实扩展消息的哈希
    uint8_t real_hash[SM3_DIGEST_SIZE];
    sm3_hash(forged_msg.data(), total_len, real_hash, false);
    cout << "真实扩展哈希: " << hash_to_string(real_hash) << endl;

    // 使用长度扩展攻击计算哈希
    uint8_t attack_hash[SM3_DIGEST_SIZE];
    sm3_length_extension_attack(original_hash, msg.size(),
        (const uint8_t*)ext.c_str(), ext.size(),
        attack_hash, false);
    cout << "攻击生成哈希: " << hash_to_string(attack_hash) << endl;

    // 验证结果是否一致
    return memcmp(real_hash, attack_hash, SM3_DIGEST_SIZE) == 0;
}

// Merkle树节点结构
struct MerkleNode {
    string hash;  // 节点哈希值
    unique_ptr<MerkleNode> left;  // 左子节点
    unique_ptr<MerkleNode> right; // 右子节点

    // 构造函数
    MerkleNode(string h, unique_ptr<MerkleNode> l = nullptr, unique_ptr<MerkleNode> r = nullptr)
        : hash(h), left(move(l)), right(move(r)) {
    }
};

// Merkle树实现（支持存在性和不存在性证明）
class MerkleTree {
private:
    vector<pair<string, string>> sorted_leaves;  // 排序的叶子数据（键）及其哈希（值）
    vector<unique_ptr<MerkleNode>> leaf_nodes;   // 叶子节点对象
    unique_ptr<MerkleNode> root;                 // 根节点

    // 合并两个哈希（核心修复：使用字节级操作而非字符串拼接）
    string merge_hash(const string& a, const string& b) const {
        uint8_t a_bytes[SM3_DIGEST_SIZE] = { 0 };  // 哈希a的原始字节
        uint8_t b_bytes[SM3_DIGEST_SIZE] = { 0 };  // 哈希b的原始字节

        // 将哈希字符串转换为字节数组（失败返回空）
        if (!string_to_hash(a, a_bytes) || !string_to_hash(b, b_bytes)) {
            return "";
        }

        // 构造内部节点输入：0x01前缀 + a字节 + b字节（符合RFC6962标准）
        uint8_t input[1 + SM3_DIGEST_SIZE * 2];
        input[0] = 0x01;  // 内部节点前缀
        memcpy(input + 1, a_bytes, SM3_DIGEST_SIZE);
        memcpy(input + 1 + SM3_DIGEST_SIZE, b_bytes, SM3_DIGEST_SIZE);

        // 计算合并后的哈希
        uint8_t digest[SM3_DIGEST_SIZE];
        sm3_hash(input, sizeof(input), digest, false);
        return hash_to_string(digest);
    }

    // 递归构建Merkle树
    unique_ptr<MerkleNode> build_tree(vector<unique_ptr<MerkleNode>> nodes) {
        if (nodes.size() == 1) {
            return move(nodes[0]);  // 只剩一个节点时返回
        }

        vector<unique_ptr<MerkleNode>> new_nodes;
        for (size_t i = 0; i < nodes.size(); i += 2) {
            if (i + 1 < nodes.size()) {
                // 合并两个节点
                string h = merge_hash(nodes[i]->hash, nodes[i + 1]->hash);
                new_nodes.push_back(make_unique<MerkleNode>(h, move(nodes[i]), move(nodes[i + 1])));
            }
            else {
                // 奇数个节点时，最后一个节点与自身合并
                string h = merge_hash(nodes[i]->hash, nodes[i]->hash);
                new_nodes.push_back(make_unique<MerkleNode>(h, move(nodes[i]), nullptr));
                new_nodes.back()->right = move(new_nodes.back()->left);  // 右子树指向自身
            }
        }
        return build_tree(move(new_nodes));  // 递归构建上一层
    }

    // 查找存在性证明路径（递归）
    bool find_path(const MerkleNode* node, const string& target, vector<pair<string, bool>>& path) const {
        if (!node) return false;

        // 找到目标叶子节点（无左右子树）
        if (node->hash == target && !node->left && !node->right) {
            return true;
        }

        // 先在左子树查找
        bool found = find_path(node->left.get(), target, path);
        if (found) {
            if (node->right) {
                // 当前节点在左子树，记录右兄弟哈希，标记为true（当前在左）
                path.emplace_back(node->right->hash, true);
            }
            return true;
        }

        // 再在右子树查找
        found = find_path(node->right.get(), target, path);
        if (found) {
            if (node->left) {
                // 当前节点在右子树，记录左兄弟哈希，标记为false（当前在右）
                path.emplace_back(node->left->hash, false);
            }
            return true;
        }

        return false;  // 未找到
    }

public:
    // 构造函数：从数据构建Merkle树
    MerkleTree(const vector<string>& data) {
        // 排序数据（确保不存在性证明可通过邻居验证）
        sorted_leaves.reserve(data.size());
        for (const auto& d : data) {
            sorted_leaves.emplace_back(d, "");
        }
        sort(sorted_leaves.begin(), sorted_leaves.end());

        // 计算叶子节点哈希（带0x00前缀，符合RFC6962）
        leaf_nodes.reserve(sorted_leaves.size());
        for (auto& leaf : sorted_leaves) {
            uint8_t digest[SM3_DIGEST_SIZE];
            string input = "\x00" + leaf.first;  // 叶子节点前缀
            sm3_hash((const uint8_t*)input.c_str(), input.size(), digest, false);
            leaf.second = hash_to_string(digest);
            leaf_nodes.push_back(make_unique<MerkleNode>(leaf.second));
        }

        // 构建树
        if (!leaf_nodes.empty()) {
            root = build_tree(move(leaf_nodes));
        }
    }

    // 获取根哈希
    string get_root() const {
        return root ? root->hash : "";
    }

    // 获取存在性证明：返回从叶子到根的路径（哈希+位置标记）
    vector<pair<string, bool>> get_inclusion_proof(const string& data) const {
        vector<pair<string, bool>> path;

        // 计算叶子哈希
        uint8_t digest[SM3_DIGEST_SIZE];
        string input = "\x00" + data;
        sm3_hash((const uint8_t*)input.c_str(), input.size(), digest, false);
        string leaf_hash = hash_to_string(digest);

        // 检查数据是否存在
        auto it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(data, ""));
        if (it == sorted_leaves.end() || it->first != data) {
            return path;  // 数据不存在，返回空路径
        }

        // 查找证明路径
        find_path(root.get(), leaf_hash, path);
        return path;
    }

    // 不存在性证明结构：包含左右邻居及其存在性证明
    struct NonInclusionProof {
        string left_data;         // 左侧邻居数据
        vector<pair<string, bool>> left_proof;  // 左侧邻居的存在性证明
        string right_data;        // 右侧邻居数据
        vector<pair<string, bool>> right_proof; // 右侧邻居的存在性证明
    };

    // 获取不存在性证明：找到目标的左右邻居并返回其存在性证明
    NonInclusionProof get_non_inclusion_proof(const string& data) const {
        NonInclusionProof proof;

        // 查找数据在排序数组中的位置（使用lower_bound找到第一个≥data的元素）
        auto it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(data, ""));

        // 处理边界情况
        if (it == sorted_leaves.begin()) {
            // 数据小于所有元素 → 只有右侧邻居
            if (it != sorted_leaves.end()) {
                proof.right_data = it->first;
                proof.right_proof = get_inclusion_proof(proof.right_data);
            }
        }
        else if (it == sorted_leaves.end()) {
            // 数据大于所有元素 → 只有左侧邻居
            --it;
            proof.left_data = it->first;
            proof.left_proof = get_inclusion_proof(proof.left_data);
        }
        else {
            // 数据在两个元素之间 → 左右邻居都有
            proof.right_data = it->first;
            proof.right_proof = get_inclusion_proof(proof.right_data);
            --it;
            proof.left_data = it->first;
            proof.left_proof = get_inclusion_proof(proof.left_data);
        }

        return proof;
    }

    // 验证存在性证明：检查数据是否在树中
    bool verify_inclusion(const string& data, const vector<pair<string, bool>>& path, const string& root_hash) const {
        if (path.empty()) return false;

        // 计算叶子哈希
        uint8_t digest[SM3_DIGEST_SIZE];
        string input = "\x00" + data;
        sm3_hash((const uint8_t*)input.c_str(), input.size(), digest, false);
        string current = hash_to_string(digest);

        // 沿着证明路径向上计算，合并哈希
        for (const auto& p : path) {
            if (p.second) {
                // 当前哈希在左侧，与右侧哈希合并
                current = merge_hash(current, p.first);
            }
            else {
                // 当前哈希在右侧，与左侧哈希合并
                current = merge_hash(p.first, current);
            }
        }

        // 验证是否等于根哈希
        return current == root_hash;
    }

    // 验证不存在性证明：检查数据是否不在树中
    bool verify_non_inclusion(const string& data, const NonInclusionProof& proof, const string& root_hash) {
        bool left_ok = false, right_ok = false;

        if (!proof.left_data.empty()) {
            if (proof.left_data >= data) return false;
            left_ok = verify_inclusion(proof.left_data, proof.left_proof, root_hash);
        }
        if (!proof.right_data.empty()) {
            if (proof.right_data <= data) return false;
            right_ok = verify_inclusion(proof.right_data, proof.right_proof, root_hash);
        }

        if (left_ok && right_ok) {
            auto left_it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(proof.left_data, ""));
            auto right_it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(proof.right_data, ""));
            return (right_it - left_it) == 1;
        }
        return left_ok || right_ok;
    }

    // 检查数据是否存在（辅助函数）
    bool contains(const string& data) const {
        auto it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(data, ""));
        return (it != sorted_leaves.end() && it->first == data);
    }
};

// 性能测试函数：计算哈希耗时
double test_performance(const string& data, int iterations, bool use_simd) {
    auto start = high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        sm3_hash_string(data, use_simd);
    }
    auto end = high_resolution_clock::now();
    return duration_cast<milliseconds>(end - start).count() / 1000.0;
}

int main() {
    // 1. SM3基础功能验证
    cout << "=== SM3基础功能验证 ===" << endl;
    string test_data = "abc";
    string hash = sm3_hash_string(test_data, false);
    string expected_abc = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    cout << "SM3(\"abc\"): " << hash << endl;
    cout << "基础哈希验证: " << (hash == expected_abc ? "成功" : "失败") << endl << endl;

    // 2. 性能测试
    cout << "=== SM3性能测试 ===" << endl;
    string large_data(1024 * 1024, 'a');  // 1MB测试数据
    int iterations = 10;

    double scalar_time = test_performance(large_data, iterations, false);
    cout << "标量实现: " << scalar_time << "秒 (" << iterations << "次迭代)" << endl;

#ifdef __AVX2__
    double simd_time = test_performance(large_data, iterations, true);
    cout << "SIMD实现: " << simd_time << "秒 (" << iterations << "次迭代)" << endl;
    cout << "加速比: " << scalar_time / simd_time << "x" << endl << endl;
#else
    cout << "AVX2不支持，未进行SIMD性能测试" << endl << endl;
#endif

    // 3. 长度扩展攻击验证
    cout << "=== 长度扩展攻击验证 ===" << endl;
    bool le_result = verify_length_extension();
    cout << "长度扩展攻击验证: " << (le_result ? "成功" : "失败") << endl << endl;

    // 4. Merkle树验证（10万节点）
    cout << "=== Merkle树验证 ===" << endl;
    const int LEAF_COUNT = 100000;
    vector<string> merkle_data;
    merkle_data.reserve(LEAF_COUNT);

    // 生成测试数据
    for (int i = 0; i < LEAF_COUNT; i++) {
        merkle_data.push_back("leaf_data_" + to_string(i));
    }

    // 构建Merkle树
    auto start = high_resolution_clock::now();
    MerkleTree mt(merkle_data);
    auto end = high_resolution_clock::now();
    double build_time = duration_cast<milliseconds>(end - start).count() / 1000.0;

    cout << "10万节点Merkle树构建完成，耗时: " << build_time << "秒" << endl;
    cout << "Merkle根哈希: " << mt.get_root() << endl << endl;

    // 存在性证明测试
    string existing_leaf = "leaf_data_12345";
    auto inc_proof = mt.get_inclusion_proof(existing_leaf);
    cout << "存在性证明测试 - " << existing_leaf << endl;
    cout << "证明长度: " << inc_proof.size() << endl;
    bool inc_verify = mt.verify_inclusion(existing_leaf, inc_proof, mt.get_root());
    cout << "验证结果: " << (inc_verify ? "成功" : "失败") << endl << endl;

    // 不存在性证明
    string non_existing_leaf = "leaf_data_999999";
    auto non_inc_proof = mt.get_non_inclusion_proof(non_existing_leaf);
    cout << "不存在性证明测试 - " << non_existing_leaf << endl;
    cout << "左侧邻居: " << (non_inc_proof.left_data.empty() ? "无" : non_inc_proof.left_data) << endl;
    cout << "右侧邻居: " << (non_inc_proof.right_data.empty() ? "无" : non_inc_proof.right_data) << endl;
    cout << "验证结果: " << (mt.verify_non_inclusion(non_existing_leaf, non_inc_proof, mt.get_root()) ? "失败" : "成功") << endl;

    return 0;
}
