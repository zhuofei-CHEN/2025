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
#include <stdexcept>  // �����쳣����

using namespace std;
using namespace chrono;

// SM3���ĳ����������������ѭGM/T 0004-2012��׼��
// ��ʼ��ϣֵH0
const uint32_t SM3_H0[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// ����Tj��ǰ16��Ϊ0x79CC4519����48��Ϊ0x7A879D8A��
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

// ��ϣ������ȣ�32�ֽڣ��Ϳ��С��64�ֽڣ�
#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

// ������������
// 32λѭ������
static inline uint32_t rotl32(uint32_t x, int n) {
    n %= 32;  // ȷ����λ����0-31֮��
    return (x << n) | (x >> (32 - n));
}

// �û�����P0
static inline uint32_t P0(uint32_t x) {
    return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

// �û�����P1
static inline uint32_t P1(uint32_t x) {
    return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

// ѹ�������еĲ�������FF
static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;  // ǰ16��
    else return (x & y) | (x & z) | (y & z);  // ��48��
}

// ѹ�������еĲ�������GG
static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;  // ǰ16��
    else return (x & y) | (~x & z);  // ��48��
}

// SIMD����������AVX2ָ�֧�֣�8��32λ�������д���
// 256λ������ѭ�����ƣ�ÿ��32λԪ�ض������ƣ�
static inline __m256i rotl256_32(__m256i x, int n) {
    const __m256i mask = _mm256_set1_epi32(0xFFFFFFFF >> (32 - n));  // �������������λ��������Чλ
    __m256i lo = _mm256_slli_epi32(x, n);  // ����
    __m256i hi = _mm256_and_si256(_mm256_srli_epi32(x, 32 - n), mask);  // ���Ʋ�����
    return _mm256_or_si256(lo, hi);  // �ϲ����
}

// �������û�����P0
static inline __m256i P0_256(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl256_32(x, 9)), rotl256_32(x, 17));
}

// �������û�����P1
static inline __m256i P1_256(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, rotl256_32(x, 15)), rotl256_32(x, 23));
}

// �����沼������FF��ǰ16�֣�
static inline __m256i FF0_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

// �����沼������FF����48�֣�
static inline __m256i FF1_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(x, z)), _mm256_and_si256(y, z));
}

// �����沼������GG��ǰ16�֣�
static inline __m256i GG0_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

// �����沼������GG����48�֣�
static inline __m256i GG1_256(__m256i x, __m256i y, __m256i z) {
    return _mm256_or_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z));
}

// �ֽ���ת�����루��С�˴洢��4�ֽ�����ת��Ϊ��ˣ�
alignas(32) const uint8_t swap_mask_data[32] = {
    3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12,
    19,18,17,16, 23,22,21,20, 27,26,25,24, 31,30,29,28
};
const __m256i swap_mask = _mm256_loadu_si256((const __m256i*)swap_mask_data);

// SM3�����Ľṹ�����ڹ�ϣ��������е�״̬���棩
struct SM3Context {
    uint32_t state[8];      // ��ǰ��ϣ״̬
    uint64_t length;        // ��Ϣ�ܳ��ȣ����أ�
    uint8_t buffer[SM3_BLOCK_SIZE];  // ��Ϣ�黺����
    int ptr;                // ��������ǰλ��
};

// ��ʼ��SM3������
void sm3_init(SM3Context* ctx) {
    if (!ctx) return;
    memcpy(ctx->state, SM3_H0, sizeof(SM3_H0));  // ��ʼ��ΪH0
    ctx->length = 0;
    ctx->ptr = 0;
}

// ����ѹ��������������512������Ϣ�飩
void sm3_compress_basic(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68] = { 0 };   // ��Ϣ��չ��W0-W67
    uint32_t W1[64] = { 0 };  // ��Ϣ��չ��W'0-W'63
    uint32_t A, B, C, D, E, F, G, H;  // ѹ�������е��м����
    int j;

    // ��Ϣ��չ������W0-W15������Ϣ��ת����
    for (j = 0; j < 16; j++) {
        W[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) |
            (block[j * 4 + 2] << 8) | block[j * 4 + 3];
    }

    // ��Ϣ��չ������W16-W67
    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15)) ^
            rotl32(W[j - 13], 7) ^ W[j - 6];
    }

    // ��Ϣ��չ������W'0-W'63
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // ��ʼ��ѹ������
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    // 64��ѹ��
    for (j = 0; j < 64; j++) {
        uint32_t SS1 = rotl32(rotl32(A, 12) + E + rotl32(SM3_T[j], j), 7);
        uint32_t SS2 = SS1 ^ rotl32(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        // ����ѹ������
        D = C;
        C = rotl32(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = rotl32(F, 19);
        F = E;
        E = P0(TT2);
    }

    // ���¹�ϣ״̬
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// SIMDѹ��������ʹ��AVX2ָ����д�������ѹ�����̣�
void sm3_compress_simd(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE]) {
    // ��̬����32�ֽڶ�����ڴ棨����ջ��������ԭջ�����飩
    alignas(32) uint32_t* W = static_cast<uint32_t*>(_aligned_malloc(68 * sizeof(uint32_t), 32));
    alignas(32) uint32_t* W1 = static_cast<uint32_t*>(_aligned_malloc(64 * sizeof(uint32_t), 32));
    if (!W || !W1) {
        throw bad_alloc();  // �ڴ����ʧ��ʱ�׳��쳣
    }
    memset(W, 0, 68 * sizeof(uint32_t));
    memset(W1, 0, 64 * sizeof(uint32_t));

    // ��Ϣ��չ������W0-W15���޸��ֽ���С�ˡ���ˣ�
    __m256i block_vec = _mm256_loadu_si256((const __m256i*)block);  // ����ǰ32�ֽ�
    block_vec = _mm256_shuffle_epi8(block_vec, swap_mask);  // �ֽ���ת��
    _mm256_store_si256((__m256i*) & W[0], block_vec);  // �洢W0-W7

    block_vec = _mm256_loadu_si256((const __m256i*) & block[32]);  // ���غ�32�ֽ�
    block_vec = _mm256_shuffle_epi8(block_vec, swap_mask);  // �ֽ���ת��
    _mm256_store_si256((__m256i*) & W[8], block_vec);  // �洢W8-W15

    // ��Ϣ��չ������W16-W63��8�鲢�д�������Խ�磩
    for (int i = 16; i <= 60; i += 8) {
        __m256i w_16 = _mm256_load_si256((__m256i*) & W[i - 16]);  // W[i-16..i-9]
        __m256i w_9 = _mm256_load_si256((__m256i*) & W[i - 9]);    // W[i-9..i-2]
        __m256i w_3 = _mm256_load_si256((__m256i*) & W[i - 3]);    // W[i-3..i+4]
        __m256i w_13 = _mm256_load_si256((__m256i*) & W[i - 13]);  // W[i-13..i-6]
        __m256i w_6 = _mm256_load_si256((__m256i*) & W[i - 6]);    // W[i-6..i+1]

        // ���м���W[i..i+7]
        __m256i temp = _mm256_xor_si256(_mm256_xor_si256(w_16, w_9), rotl256_32(w_3, 15));
        temp = P1_256(temp);
        temp = _mm256_xor_si256(_mm256_xor_si256(temp, rotl256_32(w_13, 7)), w_6);

        _mm256_store_si256((__m256i*) & W[i], temp);
    }

    // ��ȫW64-W67��������������Խ�磩
    for (int j = 64; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15)) ^
            rotl32(W[j - 13], 7) ^ W[j - 6];
    }

    // ����W1[0..63]��8�鲢�У�
    for (int i = 0; i < 64; i += 8) {
        __m256i w = _mm256_load_si256((__m256i*) & W[i]);
        __m256i w4 = _mm256_load_si256((__m256i*) & W[i + 4]);
        _mm256_store_si256((__m256i*) & W1[i], _mm256_xor_si256(w, w4));  // W1[i] = W[i] ^ W[i+4]
    }

    // ��ʼ������ѹ��������ÿ��Ԫ�ظ���8�Σ�ʵ�ֲ��д���
    __m256i A = _mm256_set1_epi32(state[0]);
    __m256i B = _mm256_set1_epi32(state[1]);
    __m256i C = _mm256_set1_epi32(state[2]);
    __m256i D = _mm256_set1_epi32(state[3]);
    __m256i E = _mm256_set1_epi32(state[4]);
    __m256i F = _mm256_set1_epi32(state[5]);
    __m256i G = _mm256_set1_epi32(state[6]);
    __m256i H = _mm256_set1_epi32(state[7]);

    // 64��ѹ����8��һ�鲢�д���
    alignas(32) uint32_t T_vec[8];  // �洢Tj����ת���
    for (int i = 0; i < 64; i += 8) {
        // Ԥ���㵱ǰ8�ֵ�Tj��ת���
        for (int j = 0; j < 8; j++) {
            T_vec[j] = rotl32(SM3_T[i + j], i + j);
        }
        __m256i T_val = _mm256_load_si256((__m256i*)T_vec);
        __m256i Wi = _mm256_load_si256((__m256i*) & W[i]);
        __m256i W1i = _mm256_load_si256((__m256i*) & W1[i]);

        // ����SS1��SS2
        __m256i rotA12 = rotl256_32(A, 12);
        __m256i SS1 = rotl256_32(_mm256_add_epi32(_mm256_add_epi32(rotA12, E), T_val), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, rotA12);

        // ����TT1��TT2����ǰ16�ֺͺ�48�֣�
        __m256i TT1, TT2;
        if (i < 16) {
            TT1 = _mm256_add_epi32(_mm256_add_epi32(FF0_256(A, B, C), D), _mm256_add_epi32(SS2, W1i));
            TT2 = _mm256_add_epi32(_mm256_add_epi32(GG0_256(E, F, G), H), _mm256_add_epi32(SS1, Wi));
        }
        else {
            TT1 = _mm256_add_epi32(_mm256_add_epi32(FF1_256(A, B, C), D), _mm256_add_epi32(SS2, W1i));
            TT2 = _mm256_add_epi32(_mm256_add_epi32(GG1_256(E, F, G), H), _mm256_add_epi32(SS1, Wi));
        }

        // ����ѹ������
        D = C; C = rotl256_32(B, 9); B = A; A = TT1;
        H = G; G = rotl256_32(F, 19); F = E; E = P0_256(TT2);
    }

    // ���¹�ϣ״̬���ϲ�8�����н����
    __m256i state_low = _mm256_load_si256((__m256i*)state);
    state_low = _mm256_xor_si256(state_low, A);
    _mm256_store_si256((__m256i*)state, state_low);

    __m256i state_high = _mm256_load_si256((__m256i*) & state[4]);
    state_high = _mm256_xor_si256(state_high, E);
    _mm256_store_si256((__m256i*) & state[4], state_high);

    // �ͷŶ��ڴ棨�����ڴ�й©��
    _aligned_free(W);
    _aligned_free(W1);
}

// ����SM3�����ģ������������ݣ�
void sm3_update(SM3Context* ctx, const uint8_t* data, size_t len, bool use_simd = false) {
    if (!ctx || !data || len == 0) return;

    // �����������ݣ����������������ѹ������
    while (len > 0) {
        int copy = SM3_BLOCK_SIZE - ctx->ptr;  // ����ɸ��Ƶ��ֽ���
        if (copy > (int)len) copy = (int)len;
        memcpy(ctx->buffer + ctx->ptr, data, copy);  // �������ݵ�������
        ctx->ptr += copy;
        data += copy;
        len -= copy;
        ctx->length += copy * 8;  // �����ܳ��ȣ����أ�

        // ��������ʱ����ѹ��
        if (ctx->ptr == SM3_BLOCK_SIZE) {
            if (use_simd) sm3_compress_simd(ctx->state, ctx->buffer);
            else sm3_compress_basic(ctx->state, ctx->buffer);
            ctx->ptr = 0;  // ���û�����
        }
    }
}

// ���SM3��ϣ���㣨������������ѹ����
void sm3_final(SM3Context* ctx, uint8_t digest[SM3_DIGEST_SIZE], bool use_simd = false) {
    if (!ctx || !digest) return;

    uint64_t final_length = ctx->length;
    int final_ptr = ctx->ptr;

    // �����Ϣ�����0x80������0
    ctx->buffer[final_ptr++] = 0x80;
    if (final_ptr > 56) {  // ������ʣ��ռ䲻��洢���ȣ�8�ֽڣ�
        memset(ctx->buffer + final_ptr, 0, SM3_BLOCK_SIZE - final_ptr);
        if (use_simd) sm3_compress_simd(ctx->state, ctx->buffer);
        else sm3_compress_basic(ctx->state, ctx->buffer);
        final_ptr = 0;
    }
    memset(ctx->buffer + final_ptr, 0, 56 - final_ptr);  // ���0��56�ֽ�

    // ������Ϣ�ܳ��ȣ�64���أ���˴洢��
    uint64_t len_bits = final_length;
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (len_bits >> (8 * (7 - i))) & 0xFF;
    }

    // ���һ��ѹ��
    if (use_simd) sm3_compress_simd(ctx->state, ctx->buffer);
    else sm3_compress_basic(ctx->state, ctx->buffer);

    // �����ϣ���������ֽ���
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

// ����SM3��ϣ����ݺ�����
void sm3_hash(const uint8_t* data, size_t len, uint8_t digest[SM3_DIGEST_SIZE], bool use_simd = false) {
    SM3Context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len, use_simd);
    sm3_final(&ctx, digest, use_simd);
}

// �ӹ�ϣֵ�ָ�״̬�����ڳ�����չ������
void sm3_recover_state(const uint8_t* hash, uint32_t state[8]) {
    if (!hash || !state) return;
    for (int i = 0; i < 8; i++) {
        state[i] = (hash[i * 4] << 24) | (hash[i * 4 + 1] << 16) |
            (hash[i * 4 + 2] << 8) | hash[i * 4 + 3];
    }
}

// ������䳤�ȣ����ڳ�����չ������
size_t sm3_calculate_pad_length(size_t original_len) {
    size_t total_required = original_len + 1 + 8;  // ����+0x80+����(8�ֽ�)
    size_t remainder = total_required % SM3_BLOCK_SIZE;
    return remainder == 0 ? 0 : SM3_BLOCK_SIZE - remainder;
}

// ������չ����ʵ��
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
    sm3_recover_state(original_hash, ctx.state);  // ��ԭʼ��ϣ�ָ�״̬

    // ������䳤�Ȳ������ܳ��ȣ�ԭʼ����+�����ܳ��ȣ�
    size_t pad_len = 1 + sm3_calculate_pad_length(original_len) + 8;
    ctx.length = (original_len + pad_len) * 8;

    // ������չ����
    sm3_update(&ctx, extension, ext_len, use_simd);
    sm3_final(&ctx, result_hash, use_simd);
}

// ��ϣֵתΪ�ַ�����16���ƣ�
string hash_to_string(const uint8_t* digest) {
    if (!digest) return "";
    stringstream ss;
    ss << hex << setfill('0');  // ���0�Ա�֤2λ16������
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        ss << setw(2) << (int)digest[i];  // ÿ���ֽ�תΪ2λ16����
    }
    return ss.str();
}

// �ַ���תΪ��ϣֵ��16�����ַ������ֽ����飩
bool string_to_hash(const string& hash_str, uint8_t* digest) {
    if (hash_str.length() != 2 * SM3_DIGEST_SIZE || !digest) return false;

    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        string byte_str = hash_str.substr(i * 2, 2);  // ��ȡ2���ַ���1���ֽڣ�
        digest[i] = (uint8_t)stoul(byte_str, nullptr, 16);  // תΪ�ֽ�
    }
    return true;
}

// ��ݵ��ַ�����ϣ����
string sm3_hash_string(const string& data, bool use_simd = false) {
    uint8_t digest[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t*)data.c_str(), data.size(), digest, use_simd);
    return hash_to_string(digest);
}

// ��֤������չ����
bool verify_length_extension() {
    const string msg = "secret message";
    const string ext = "extended data";

    // ����ԭʼ��Ϣ��ϣ
    uint8_t original_hash[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t*)msg.c_str(), msg.size(), original_hash, false);
    cout << "ԭʼ��Ϣ��ϣ: " << hash_to_string(original_hash) << endl;

    // ������ʵ����չ��Ϣ��ԭʼ��Ϣ + ��� + ��չ���ݣ�
    size_t pad_len = sm3_calculate_pad_length(msg.size());
    size_t total_len = msg.size() + 1 + pad_len + 8 + ext.size();
    vector<uint8_t> forged_msg(total_len);

    // ����ԭʼ��Ϣ
    memcpy(forged_msg.data(), msg.c_str(), msg.size());
    size_t ptr = msg.size();

    // ������
    forged_msg[ptr++] = 0x80;
    if (pad_len > 0) {
        memset(forged_msg.data() + ptr, 0, pad_len);
        ptr += pad_len;
    }

    // ��ӳ��ȣ�64���أ�
    uint64_t len_bits = (uint64_t)msg.size() * 8;
    for (int i = 0; i < 8; i++) {
        forged_msg[ptr++] = (len_bits >> (8 * (7 - i))) & 0xFF;
    }

    // �����չ����
    memcpy(forged_msg.data() + ptr, ext.c_str(), ext.size());

    // ������ʵ��չ��Ϣ�Ĺ�ϣ
    uint8_t real_hash[SM3_DIGEST_SIZE];
    sm3_hash(forged_msg.data(), total_len, real_hash, false);
    cout << "��ʵ��չ��ϣ: " << hash_to_string(real_hash) << endl;

    // ʹ�ó�����չ���������ϣ
    uint8_t attack_hash[SM3_DIGEST_SIZE];
    sm3_length_extension_attack(original_hash, msg.size(),
        (const uint8_t*)ext.c_str(), ext.size(),
        attack_hash, false);
    cout << "�������ɹ�ϣ: " << hash_to_string(attack_hash) << endl;

    // ��֤����Ƿ�һ��
    return memcmp(real_hash, attack_hash, SM3_DIGEST_SIZE) == 0;
}

// Merkle���ڵ�ṹ
struct MerkleNode {
    string hash;  // �ڵ��ϣֵ
    unique_ptr<MerkleNode> left;  // ���ӽڵ�
    unique_ptr<MerkleNode> right; // ���ӽڵ�

    // ���캯��
    MerkleNode(string h, unique_ptr<MerkleNode> l = nullptr, unique_ptr<MerkleNode> r = nullptr)
        : hash(h), left(move(l)), right(move(r)) {
    }
};

// Merkle��ʵ�֣�֧�ִ����ԺͲ�������֤����
class MerkleTree {
private:
    vector<pair<string, string>> sorted_leaves;  // �����Ҷ�����ݣ����������ϣ��ֵ��
    vector<unique_ptr<MerkleNode>> leaf_nodes;   // Ҷ�ӽڵ����
    unique_ptr<MerkleNode> root;                 // ���ڵ�

    // �ϲ�������ϣ�������޸���ʹ���ֽڼ����������ַ���ƴ�ӣ�
    string merge_hash(const string& a, const string& b) const {
        uint8_t a_bytes[SM3_DIGEST_SIZE] = { 0 };  // ��ϣa��ԭʼ�ֽ�
        uint8_t b_bytes[SM3_DIGEST_SIZE] = { 0 };  // ��ϣb��ԭʼ�ֽ�

        // ����ϣ�ַ���ת��Ϊ�ֽ����飨ʧ�ܷ��ؿգ�
        if (!string_to_hash(a, a_bytes) || !string_to_hash(b, b_bytes)) {
            return "";
        }

        // �����ڲ��ڵ����룺0x01ǰ׺ + a�ֽ� + b�ֽڣ�����RFC6962��׼��
        uint8_t input[1 + SM3_DIGEST_SIZE * 2];
        input[0] = 0x01;  // �ڲ��ڵ�ǰ׺
        memcpy(input + 1, a_bytes, SM3_DIGEST_SIZE);
        memcpy(input + 1 + SM3_DIGEST_SIZE, b_bytes, SM3_DIGEST_SIZE);

        // ����ϲ���Ĺ�ϣ
        uint8_t digest[SM3_DIGEST_SIZE];
        sm3_hash(input, sizeof(input), digest, false);
        return hash_to_string(digest);
    }

    // �ݹ鹹��Merkle��
    unique_ptr<MerkleNode> build_tree(vector<unique_ptr<MerkleNode>> nodes) {
        if (nodes.size() == 1) {
            return move(nodes[0]);  // ֻʣһ���ڵ�ʱ����
        }

        vector<unique_ptr<MerkleNode>> new_nodes;
        for (size_t i = 0; i < nodes.size(); i += 2) {
            if (i + 1 < nodes.size()) {
                // �ϲ������ڵ�
                string h = merge_hash(nodes[i]->hash, nodes[i + 1]->hash);
                new_nodes.push_back(make_unique<MerkleNode>(h, move(nodes[i]), move(nodes[i + 1])));
            }
            else {
                // �������ڵ�ʱ�����һ���ڵ�������ϲ�
                string h = merge_hash(nodes[i]->hash, nodes[i]->hash);
                new_nodes.push_back(make_unique<MerkleNode>(h, move(nodes[i]), nullptr));
                new_nodes.back()->right = move(new_nodes.back()->left);  // ������ָ������
            }
        }
        return build_tree(move(new_nodes));  // �ݹ鹹����һ��
    }

    // ���Ҵ�����֤��·�����ݹ飩
    bool find_path(const MerkleNode* node, const string& target, vector<pair<string, bool>>& path) const {
        if (!node) return false;

        // �ҵ�Ŀ��Ҷ�ӽڵ㣨������������
        if (node->hash == target && !node->left && !node->right) {
            return true;
        }

        // ��������������
        bool found = find_path(node->left.get(), target, path);
        if (found) {
            if (node->right) {
                // ��ǰ�ڵ�������������¼���ֵܹ�ϣ�����Ϊtrue����ǰ����
                path.emplace_back(node->right->hash, true);
            }
            return true;
        }

        // ��������������
        found = find_path(node->right.get(), target, path);
        if (found) {
            if (node->left) {
                // ��ǰ�ڵ�������������¼���ֵܹ�ϣ�����Ϊfalse����ǰ���ң�
                path.emplace_back(node->left->hash, false);
            }
            return true;
        }

        return false;  // δ�ҵ�
    }

public:
    // ���캯���������ݹ���Merkle��
    MerkleTree(const vector<string>& data) {
        // �������ݣ�ȷ����������֤����ͨ���ھ���֤��
        sorted_leaves.reserve(data.size());
        for (const auto& d : data) {
            sorted_leaves.emplace_back(d, "");
        }
        sort(sorted_leaves.begin(), sorted_leaves.end());

        // ����Ҷ�ӽڵ��ϣ����0x00ǰ׺������RFC6962��
        leaf_nodes.reserve(sorted_leaves.size());
        for (auto& leaf : sorted_leaves) {
            uint8_t digest[SM3_DIGEST_SIZE];
            string input = "\x00" + leaf.first;  // Ҷ�ӽڵ�ǰ׺
            sm3_hash((const uint8_t*)input.c_str(), input.size(), digest, false);
            leaf.second = hash_to_string(digest);
            leaf_nodes.push_back(make_unique<MerkleNode>(leaf.second));
        }

        // ������
        if (!leaf_nodes.empty()) {
            root = build_tree(move(leaf_nodes));
        }
    }

    // ��ȡ����ϣ
    string get_root() const {
        return root ? root->hash : "";
    }

    // ��ȡ������֤�������ش�Ҷ�ӵ�����·������ϣ+λ�ñ�ǣ�
    vector<pair<string, bool>> get_inclusion_proof(const string& data) const {
        vector<pair<string, bool>> path;

        // ����Ҷ�ӹ�ϣ
        uint8_t digest[SM3_DIGEST_SIZE];
        string input = "\x00" + data;
        sm3_hash((const uint8_t*)input.c_str(), input.size(), digest, false);
        string leaf_hash = hash_to_string(digest);

        // ��������Ƿ����
        auto it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(data, ""));
        if (it == sorted_leaves.end() || it->first != data) {
            return path;  // ���ݲ����ڣ����ؿ�·��
        }

        // ����֤��·��
        find_path(root.get(), leaf_hash, path);
        return path;
    }

    // ��������֤���ṹ�����������ھӼ��������֤��
    struct NonInclusionProof {
        string left_data;         // ����ھ�����
        vector<pair<string, bool>> left_proof;  // ����ھӵĴ�����֤��
        string right_data;        // �Ҳ��ھ�����
        vector<pair<string, bool>> right_proof; // �Ҳ��ھӵĴ�����֤��
    };

    // ��ȡ��������֤�����ҵ�Ŀ��������ھӲ������������֤��
    NonInclusionProof get_non_inclusion_proof(const string& data) const {
        NonInclusionProof proof;

        // �������������������е�λ�ã�ʹ��lower_bound�ҵ���һ����data��Ԫ�أ�
        auto it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(data, ""));

        // ����߽����
        if (it == sorted_leaves.begin()) {
            // ����С������Ԫ�� �� ֻ���Ҳ��ھ�
            if (it != sorted_leaves.end()) {
                proof.right_data = it->first;
                proof.right_proof = get_inclusion_proof(proof.right_data);
            }
        }
        else if (it == sorted_leaves.end()) {
            // ���ݴ�������Ԫ�� �� ֻ������ھ�
            --it;
            proof.left_data = it->first;
            proof.left_proof = get_inclusion_proof(proof.left_data);
        }
        else {
            // ����������Ԫ��֮�� �� �����ھӶ���
            proof.right_data = it->first;
            proof.right_proof = get_inclusion_proof(proof.right_data);
            --it;
            proof.left_data = it->first;
            proof.left_proof = get_inclusion_proof(proof.left_data);
        }

        return proof;
    }

    // ��֤������֤������������Ƿ�������
    bool verify_inclusion(const string& data, const vector<pair<string, bool>>& path, const string& root_hash) const {
        if (path.empty()) return false;

        // ����Ҷ�ӹ�ϣ
        uint8_t digest[SM3_DIGEST_SIZE];
        string input = "\x00" + data;
        sm3_hash((const uint8_t*)input.c_str(), input.size(), digest, false);
        string current = hash_to_string(digest);

        // ����֤��·�����ϼ��㣬�ϲ���ϣ
        for (const auto& p : path) {
            if (p.second) {
                // ��ǰ��ϣ����࣬���Ҳ��ϣ�ϲ�
                current = merge_hash(current, p.first);
            }
            else {
                // ��ǰ��ϣ���Ҳ࣬������ϣ�ϲ�
                current = merge_hash(p.first, current);
            }
        }

        // ��֤�Ƿ���ڸ���ϣ
        return current == root_hash;
    }

    // ��֤��������֤������������Ƿ�������
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

    // ��������Ƿ���ڣ�����������
    bool contains(const string& data) const {
        auto it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), make_pair(data, ""));
        return (it != sorted_leaves.end() && it->first == data);
    }
};

// ���ܲ��Ժ����������ϣ��ʱ
double test_performance(const string& data, int iterations, bool use_simd) {
    auto start = high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        sm3_hash_string(data, use_simd);
    }
    auto end = high_resolution_clock::now();
    return duration_cast<milliseconds>(end - start).count() / 1000.0;
}

int main() {
    // 1. SM3����������֤
    cout << "=== SM3����������֤ ===" << endl;
    string test_data = "abc";
    string hash = sm3_hash_string(test_data, false);
    string expected_abc = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    cout << "SM3(\"abc\"): " << hash << endl;
    cout << "������ϣ��֤: " << (hash == expected_abc ? "�ɹ�" : "ʧ��") << endl << endl;

    // 2. ���ܲ���
    cout << "=== SM3���ܲ��� ===" << endl;
    string large_data(1024 * 1024, 'a');  // 1MB��������
    int iterations = 10;

    double scalar_time = test_performance(large_data, iterations, false);
    cout << "����ʵ��: " << scalar_time << "�� (" << iterations << "�ε���)" << endl;

#ifdef __AVX2__
    double simd_time = test_performance(large_data, iterations, true);
    cout << "SIMDʵ��: " << simd_time << "�� (" << iterations << "�ε���)" << endl;
    cout << "���ٱ�: " << scalar_time / simd_time << "x" << endl << endl;
#else
    cout << "AVX2��֧�֣�δ����SIMD���ܲ���" << endl << endl;
#endif

    // 3. ������չ������֤
    cout << "=== ������չ������֤ ===" << endl;
    bool le_result = verify_length_extension();
    cout << "������չ������֤: " << (le_result ? "�ɹ�" : "ʧ��") << endl << endl;

    // 4. Merkle����֤��10��ڵ㣩
    cout << "=== Merkle����֤ ===" << endl;
    const int LEAF_COUNT = 100000;
    vector<string> merkle_data;
    merkle_data.reserve(LEAF_COUNT);

    // ���ɲ�������
    for (int i = 0; i < LEAF_COUNT; i++) {
        merkle_data.push_back("leaf_data_" + to_string(i));
    }

    // ����Merkle��
    auto start = high_resolution_clock::now();
    MerkleTree mt(merkle_data);
    auto end = high_resolution_clock::now();
    double build_time = duration_cast<milliseconds>(end - start).count() / 1000.0;

    cout << "10��ڵ�Merkle��������ɣ���ʱ: " << build_time << "��" << endl;
    cout << "Merkle����ϣ: " << mt.get_root() << endl << endl;

    // ������֤������
    string existing_leaf = "leaf_data_12345";
    auto inc_proof = mt.get_inclusion_proof(existing_leaf);
    cout << "������֤������ - " << existing_leaf << endl;
    cout << "֤������: " << inc_proof.size() << endl;
    bool inc_verify = mt.verify_inclusion(existing_leaf, inc_proof, mt.get_root());
    cout << "��֤���: " << (inc_verify ? "�ɹ�" : "ʧ��") << endl << endl;

    // ��������֤��
    string non_existing_leaf = "leaf_data_999999";
    auto non_inc_proof = mt.get_non_inclusion_proof(non_existing_leaf);
    cout << "��������֤������ - " << non_existing_leaf << endl;
    cout << "����ھ�: " << (non_inc_proof.left_data.empty() ? "��" : non_inc_proof.left_data) << endl;
    cout << "�Ҳ��ھ�: " << (non_inc_proof.right_data.empty() ? "��" : non_inc_proof.right_data) << endl;
    cout << "��֤���: " << (mt.verify_non_inclusion(non_existing_leaf, non_inc_proof, mt.get_root()) ? "ʧ��" : "�ɹ�") << endl;

    return 0;
}
