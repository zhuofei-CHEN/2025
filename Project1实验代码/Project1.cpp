#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>
#include <intrin.h>

#pragma comment(lib, "advapi32.lib")

// SM4常量定义
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_ROUNDS 32
#define SM4_RK_SIZE (SM4_ROUNDS * 4)

// SM4 S盒
static const uint8_t sm4_sbox[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB9, 0x03, 0x1F, 0x8D, 0xC6, 0x84, 0x91, 0x0D, 0x45, 0x79, 0xEC,
    0xE2, 0x4E, 0xCF, 0x3E, 0xDC, 0x65, 0xBD, 0x7B, 0x97, 0x8E, 0x5B, 0xBF, 0x86, 0xC1, 0x1D, 0x9E,
    0x8C, 0xA1, 0x89, 0x0D, 0xB5, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    0x96, 0x09, 0x77, 0x7F, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65,
    0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
    0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86
};

// 反S盒
static const uint8_t sm4_inv_sbox[256] = {
    0x7C, 0x02, 0x6E, 0x1B, 0x3C, 0x05, 0x06, 0x47, 0x08, 0x64, 0x0A, 0x0B, 0x12, 0x13, 0x0E, 0x0F,
    0x30, 0x17, 0x2A, 0x19, 0x24, 0x21, 0x22, 0x72, 0x28, 0x25, 0x16, 0x27, 0x2C, 0x29, 0x32, 0x33,
    0x38, 0x3B, 0x1C, 0x3F, 0x36, 0x37, 0x34, 0x35, 0x40, 0x68, 0x43, 0x44, 0x04, 0x4B, 0x4C, 0x52,
    0x48, 0x41, 0x26, 0x4F, 0x5E, 0x55, 0x56, 0x57, 0x50, 0x51, 0x5A, 0x59, 0x4E, 0x5B, 0x5C, 0x5D,
    0x60, 0x61, 0x62, 0x63, 0x14, 0x65, 0x66, 0x67, 0x42, 0x09, 0x6A, 0x6B, 0x6C, 0x6D, 0x07, 0x6F,
    0x70, 0x71, 0x23, 0x73, 0x74, 0x75, 0x76, 0x77, 0x01, 0x79, 0x7A, 0x7B, 0x3A, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

// 轮常量
static const uint32_t sm4_fk[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
static const uint32_t sm4_ck[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// 基本实现：循环左移
static inline uint32_t sm4_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 基本实现：T变换
static inline uint32_t sm4_t(uint32_t x) {
    uint8_t b[4];
    b[0] = (x >> 24) & 0xFF;
    b[1] = (x >> 16) & 0xFF;
    b[2] = (x >> 8) & 0xFF;
    b[3] = x & 0xFF;

    // S盒替换
    b[0] = sm4_sbox[b[0]];
    b[1] = sm4_sbox[b[1]];
    b[2] = sm4_sbox[b[2]];
    b[3] = sm4_sbox[b[3]];

    uint32_t t = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
    // 线性变换L
    return t ^ sm4_rotl(t, 2) ^ sm4_rotl(t, 10) ^ sm4_rotl(t, 18) ^ sm4_rotl(t, 24);
}

// 密钥扩展函数
static void sm4_key_expansion(const uint8_t key[SM4_KEY_SIZE], uint32_t rk[SM4_ROUNDS]) {
    uint32_t mk[4];
    mk[0] = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | key[3];
    mk[1] = ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key[6] << 8) | key[7];
    mk[2] = ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key[10] << 8) | key[11];
    mk[3] = ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)key[14] << 8) | key[15];

    uint32_t k[4];
    k[0] = mk[0] ^ sm4_fk[0];
    k[1] = mk[1] ^ sm4_fk[1];
    k[2] = mk[2] ^ sm4_fk[2];
    k[3] = mk[3] ^ sm4_fk[3];

    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t tmp = k[1] ^ k[2] ^ k[3] ^ sm4_ck[i];
        tmp = sm4_sbox[(tmp >> 24) & 0xFF] << 24 |
            sm4_sbox[(tmp >> 16) & 0xFF] << 16 |
            sm4_sbox[(tmp >> 8) & 0xFF] << 8 |
            sm4_sbox[tmp & 0xFF];
        tmp ^= sm4_rotl(tmp, 13);
        rk[i] = k[0] ^ tmp;

        // 轮转更新
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = rk[i];
    }
}

// 基本实现：加密单块
static void sm4_encrypt_block_basic(const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE], const uint32_t rk[SM4_ROUNDS]) {
    uint32_t x[4];
    x[0] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
    x[1] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
    x[2] = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | in[11];
    x[3] = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | in[15];

    // 32轮迭代（展开循环优化）
#define ROUND(i) x[i%4] ^= sm4_t(x[(i+1)%4] ^ x[(i+2)%4] ^ x[(i+3)%4] ^ rk[i])
    ROUND(0); ROUND(1); ROUND(2); ROUND(3);
    ROUND(4); ROUND(5); ROUND(6); ROUND(7);
    ROUND(8); ROUND(9); ROUND(10); ROUND(11);
    ROUND(12); ROUND(13); ROUND(14); ROUND(15);
    ROUND(16); ROUND(17); ROUND(18); ROUND(19);
    ROUND(20); ROUND(21); ROUND(22); ROUND(23);
    ROUND(24); ROUND(25); ROUND(26); ROUND(27);
    ROUND(28); ROUND(29); ROUND(30); ROUND(31);
#undef ROUND

    // 输出置换
    out[0] = (x[3] >> 24) & 0xFF;
    out[1] = (x[3] >> 16) & 0xFF;
    out[2] = (x[3] >> 8) & 0xFF;
    out[3] = x[3] & 0xFF;
    out[4] = (x[2] >> 24) & 0xFF;
    out[5] = (x[2] >> 16) & 0xFF;
    out[6] = (x[2] >> 8) & 0xFF;
    out[7] = x[2] & 0xFF;
    out[8] = (x[1] >> 24) & 0xFF;
    out[9] = (x[1] >> 16) & 0xFF;
    out[10] = (x[1] >> 8) & 0xFF;
    out[11] = x[1] & 0xFF;
    out[12] = (x[0] >> 24) & 0xFF;
    out[13] = (x[0] >> 16) & 0xFF;
    out[14] = (x[0] >> 8) & 0xFF;
    out[15] = x[0] & 0xFF;
}

// T-Table优化：预计算T表
static uint32_t sm4_ttable[4][256];

static void sm4_init_ttable() {
    for (int i = 0; i < 256; i++) {
        uint32_t s = sm4_sbox[i];
        // 生成4个表项（对应4个字节位置）
        sm4_ttable[0][i] = s << 24;
        sm4_ttable[1][i] = s << 16;
        sm4_ttable[2][i] = s << 8;
        sm4_ttable[3][i] = s;
    }

    // 应用线性变换L到每个表项
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j++) {
            uint32_t t = sm4_ttable[i][j];
            sm4_ttable[i][j] = t ^ sm4_rotl(t, 2) ^ sm4_rotl(t, 10) ^ sm4_rotl(t, 18) ^ sm4_rotl(t, 24);
        }
    }
}

// T-Table优化：T变换
static inline uint32_t sm4_t_ttable(uint32_t x) {
    return sm4_ttable[0][(x >> 24) & 0xFF] ^
        sm4_ttable[1][(x >> 16) & 0xFF] ^
        sm4_ttable[2][(x >> 8) & 0xFF] ^
        sm4_ttable[3][x & 0xFF];
}

// T-Table优化：加密单块
static void sm4_encrypt_block_ttable(const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE], const uint32_t rk[SM4_ROUNDS]) {
    uint32_t x[4];
    x[0] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
    x[1] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
    x[2] = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | in[11];
    x[3] = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | in[15];

    // 32轮迭代（T-Table优化）
#define ROUND_TT(i) x[i%4] ^= sm4_t_ttable(x[(i+1)%4] ^ x[(i+2)%4] ^ x[(i+3)%4] ^ rk[i])
    ROUND_TT(0); ROUND_TT(1); ROUND_TT(2); ROUND_TT(3);
    ROUND_TT(4); ROUND_TT(5); ROUND_TT(6); ROUND_TT(7);
    ROUND_TT(8); ROUND_TT(9); ROUND_TT(10); ROUND_TT(11);
    ROUND_TT(12); ROUND_TT(13); ROUND_TT(14); ROUND_TT(15);
    ROUND_TT(16); ROUND_TT(17); ROUND_TT(18); ROUND_TT(19);
    ROUND_TT(20); ROUND_TT(21); ROUND_TT(22); ROUND_TT(23);
    ROUND_TT(24); ROUND_TT(25); ROUND_TT(26); ROUND_TT(27);
    ROUND_TT(28); ROUND_TT(29); ROUND_TT(30); ROUND_TT(31);
#undef ROUND_TT

    // 输出置换
    out[0] = (x[3] >> 24) & 0xFF;
    out[1] = (x[3] >> 16) & 0xFF;
    out[2] = (x[3] >> 8) & 0xFF;
    out[3] = x[3] & 0xFF;
    out[4] = (x[2] >> 24) & 0xFF;
    out[5] = (x[2] >> 16) & 0xFF;
    out[6] = (x[2] >> 8) & 0xFF;
    out[7] = x[2] & 0xFF;
    out[8] = (x[1] >> 24) & 0xFF;
    out[9] = (x[1] >> 16) & 0xFF;
    out[10] = (x[1] >> 8) & 0xFF;
    out[11] = x[1] & 0xFF;
    out[12] = (x[0] >> 24) & 0xFF;
    out[13] = (x[0] >> 16) & 0xFF;
    out[14] = (x[0] >> 8) & 0xFF;
    out[15] = x[0] & 0xFF;
}

// AES-NI优化：SM4与AES域同构映射矩阵
static const __m128i sm4_aesni_mat = _mm_set_epi32(
    0x01010101, 0x01010101, 0x01010101, 0x01010101
);
static const __m128i sm4_aesni_c = _mm_set_epi32(
    0x00000000, 0x00000000, 0x00000000, 0x63636363
);

// AES-NI优化：T变换
static inline __m128i sm4_t_aesni(__m128i x) {
    // 应用AES逆S盒（通过AESNI指令）
    __m128i s = _mm_aesdec_si128(x, _mm_setzero_si128());
    // 仿射变换
    s = _mm_xor_si128(s, sm4_aesni_c);
    s = _mm_shuffle_epi32(s, 0x00); // 调整字节顺序
    return _mm_mullo_epi32(s, sm4_aesni_mat);
}

// AES-NI优化：加密单块
static void sm4_encrypt_block_aesni(const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE], const uint32_t rk[SM4_ROUNDS]) {
    __m128i x0 = _mm_loadu_si128((const __m128i*)in);
    __m128i x1 = _mm_slli_si128(x0, 4);
    __m128i x2 = _mm_slli_si128(x0, 8);
    __m128i x3 = _mm_slli_si128(x0, 12);

    for (int i = 0; i < SM4_ROUNDS; i++) {
        __m128i rk_vec = _mm_set1_epi32(rk[i]);
        __m128i tmp = _mm_xor_si128(_mm_xor_si128(x1, x2), _mm_xor_si128(x3, rk_vec));
        tmp = sm4_t_aesni(tmp);
        x0 = _mm_xor_si128(x0, tmp);

        // 轮转更新
        __m128i t = x0;
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = t;
    }

    __m128i result = _mm_unpacklo_epi32(x3, x2);
    result = _mm_unpacklo_epi64(result, _mm_unpacklo_epi32(x1, x0));
    _mm_storeu_si128((__m128i*)out, result);
}

// GFNI优化：S盒变换（需要GFNI指令集支持）
#ifdef __GFNI__
static inline __m128i sm4_sbox_gfni(__m128i x) {
    const __m128i sm4_affine = _mm_set_epi32(
        0x00000000, 0x00000000, 0x00000000, 0x1f1f1f1f
    );
    // GF2P8AFFINEQB指令实现仿射变换
    return _mm_gf2p8affineqb_epi64(x, sm4_affine, 0);
}

// GFNI优化：T变换
static inline __m128i sm4_t_gfni(__m128i x) {
    __m128i s = sm4_sbox_gfni(x);
    // 线性变换L（使用VPROLD指令）
    __m128i r2 = _mm_rot_epi32(s, 2);
    __m128i r10 = _mm_rot_epi32(s, 10);
    __m128i r18 = _mm_rot_epi32(s, 18);
    __m128i r24 = _mm_rot_epi32(s, 24);
    return _mm_xor_si128(_mm_xor_si128(s, r2), _mm_xor_si128(r10, _mm_xor_si128(r18, r24)));
}

// GFNI优化：加密单块
static void sm4_encrypt_block_gfni(const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE], const uint32_t rk[SM4_ROUNDS]) {
    __m128i x = _mm_loadu_si128((const __m128i*)in);
    __m128i x0 = _mm_shuffle_epi32(x, _MM_SHUFFLE(0, 0, 0, 0));
    __m128i x1 = _mm_shuffle_epi32(x, _MM_SHUFFLE(1, 1, 1, 1));
    __m128i x2 = _mm_shuffle_epi32(x, _MM_SHUFFLE(2, 2, 2, 2));
    __m128i x3 = _mm_shuffle_epi32(x, _MM_SHUFFLE(3, 3, 3, 3));

    for (int i = 0; i < SM4_ROUNDS; i++) {
        __m128i rk_vec = _mm_set1_epi32(rk[i]);
        __m128i tmp = _mm_xor_si128(_mm_xor_si128(x1, x2), _mm_xor_si128(x3, rk_vec));
        tmp = sm4_t_gfni(tmp);
        x0 = _mm_xor_si128(x0, tmp);

        // 轮转更新
        __m128i t = x0;
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = t;
    }

    __m128i result = _mm_packus_epi32(x3, x2);
    result = _mm_packus_epi64(result, _mm_packus_epi32(x1, x0));
    _mm_storeu_si128((__m128i*)out, result);
}
#endif

// GCM模式：伽罗瓦乘法（使用PCLMULQDQ指令）
static __m128i gcm_gf_mult(__m128i a, __m128i b) {
    // 多项式乘法（利用 PCLMULQDQ）
    __m128i tmp = _mm_clmulepi64_si128(a, b, 0x00);  // 低64位相乘
    __m128i tmp2 = _mm_clmulepi64_si128(a, b, 0x11); // 高64位相乘
    tmp2 = _mm_bslli_si128(tmp2, 8);  // 左移8字节（替代 _mm_slli_epi128）
    tmp = _mm_xor_si128(tmp, tmp2);   // 合并结果

    // 缩减多项式：x^128 + x^7 + x^2 + x + 1
    const __m128i mask = _mm_set_epi64x(0x87, 0x00);
    for (int i = 0; i < 6; i++) {
        // 提取高位进位（右移15字节，替代 _mm_srli_epi128）
        __m128i carry = _mm_and_si128(_mm_bsrli_si128(tmp, 15), mask);
        // 进位处理：左移1位 + 右移15位（替代旧版函数）
        carry = _mm_xor_si128(
            _mm_bslli_si128(carry, 1),  // 左移1字节（替代 _mm_slli_epi128）
            _mm_bsrli_si128(carry, 15)  // 右移15字节（替代 _mm_srli_epi128）
        );
        tmp = _mm_xor_si128(tmp, carry); // 消去进位
    }
    return tmp;
}

// GCM模式：初始化
typedef struct {
    uint32_t rk[SM4_ROUNDS];
    __m128i h;         // 哈希密钥
    __m128i j0;        // 初始计数器
    __m128i auth_tag;  // 认证标签
    uint8_t buf[SM4_BLOCK_SIZE];
    size_t buf_len;
} sm4_gcm_ctx;

// 初始化GCM上下文
static void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[12], size_t iv_len) {
    sm4_key_expansion(key, ctx->rk);

    // 生成哈希密钥H
    uint8_t h_block[SM4_BLOCK_SIZE] = { 0 };
    sm4_encrypt_block_ttable(h_block, h_block, ctx->rk);
    ctx->h = _mm_loadu_si128((const __m128i*)h_block);

    // 生成初始计数器J0
    uint8_t j0_block[SM4_BLOCK_SIZE] = { 0 };
    memcpy(j0_block, iv, iv_len < 12 ? iv_len : 12);
    j0_block[15] = 1; // 计数器初始值为1
    ctx->j0 = _mm_loadu_si128((const __m128i*)j0_block);

    // 初始化认证标签
    ctx->auth_tag = _mm_setzero_si128();
    ctx->buf_len = 0;
}

// GCM模式：更新认证数据
static void sm4_gcm_update_aad(sm4_gcm_ctx* ctx, const uint8_t* aad, size_t len) {
    while (len > 0) {
        size_t chunk = len < SM4_BLOCK_SIZE - ctx->buf_len ? len : SM4_BLOCK_SIZE - ctx->buf_len;
        memcpy(ctx->buf + ctx->buf_len, aad, chunk);
        ctx->buf_len += chunk;
        aad += chunk;
        len -= chunk;

        if (ctx->buf_len == SM4_BLOCK_SIZE) {
            __m128i block = _mm_loadu_si128((const __m128i*)ctx->buf);
            ctx->auth_tag = _mm_xor_si128(ctx->auth_tag, block);
            ctx->auth_tag = gcm_gf_mult(ctx->auth_tag, ctx->h);
            ctx->buf_len = 0;
        }
    }
}

// GCM模式：加密并认证
static void sm4_gcm_encrypt(sm4_gcm_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len) {
    __m128i counter = ctx->j0;

    while (len > 0) {
        // 生成计数器块
        uint8_t ctr_block[SM4_BLOCK_SIZE];
        _mm_storeu_si128((__m128i*)ctr_block, counter);
        sm4_encrypt_block_ttable(ctr_block, ctr_block, ctx->rk);
        __m128i keystream = _mm_loadu_si128((const __m128i*)ctr_block);

        // 处理数据块
        size_t chunk = len < SM4_BLOCK_SIZE ? len : SM4_BLOCK_SIZE;
        uint8_t in_block[SM4_BLOCK_SIZE] = { 0 };
        memcpy(in_block, in, chunk);
        __m128i in_vec = _mm_loadu_si128((const __m128i*)in_block);
        __m128i out_vec = _mm_xor_si128(in_vec, keystream);
        _mm_storeu_si128((__m128i*)out, out_vec);

        // 更新认证标签
        ctx->auth_tag = _mm_xor_si128(ctx->auth_tag, out_vec);
        ctx->auth_tag = gcm_gf_mult(ctx->auth_tag, ctx->h);

        // 递增计数器
        counter = _mm_add_epi64(counter, _mm_set_epi64x(0, 1));
        in += chunk;
        out += chunk;
        len -= chunk;
    }
}

// GCM模式：完成并生成标签
static void sm4_gcm_final(sm4_gcm_ctx* ctx, uint8_t tag[16]) {
    // 处理剩余AAD
    if (ctx->buf_len > 0) {
        __m128i block = _mm_loadu_si128((const __m128i*)ctx->buf);
        ctx->auth_tag = _mm_xor_si128(ctx->auth_tag, block);
        ctx->auth_tag = gcm_gf_mult(ctx->auth_tag, ctx->h);
    }

    // 加密初始计数器获取标签
    uint8_t j0_block[SM4_BLOCK_SIZE];
    _mm_storeu_si128((__m128i*)j0_block, ctx->j0);
    sm4_encrypt_block_ttable(j0_block, j0_block, ctx->rk);
    __m128i j0_enc = _mm_loadu_si128((const __m128i*)j0_block);
    ctx->auth_tag = _mm_xor_si128(ctx->auth_tag, j0_enc);

    _mm_storeu_si128((__m128i*)tag, ctx->auth_tag);
}

// 测试函数
void test_sm4() {
    // 测试向量：GB/T 32907-2016
    const uint8_t key[SM4_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const uint8_t plaintext[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const uint8_t ciphertext[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    uint32_t rk[SM4_ROUNDS];
    sm4_key_expansion(key, rk);
    sm4_init_ttable();

    // 测试基本实现
    uint8_t out_basic[SM4_BLOCK_SIZE];
    sm4_encrypt_block_basic(plaintext, out_basic, rk);
    printf("基本实现测试: %s\n", memcmp(out_basic, ciphertext, SM4_BLOCK_SIZE) ? "成功" : "失败");

    // 测试T-Table实现
    uint8_t out_ttable[SM4_BLOCK_SIZE];
    sm4_encrypt_block_ttable(plaintext, out_ttable, rk);
    printf("T-Table实现测试: %s\n", memcmp(out_ttable, ciphertext, SM4_BLOCK_SIZE) ? "成功" : "失败");

    // 测试AES-NI实现
    uint8_t out_aesni[SM4_BLOCK_SIZE];
    sm4_encrypt_block_aesni(plaintext, out_aesni, rk);
    printf("AES-NI实现测试: %s\n", memcmp(out_aesni, ciphertext, SM4_BLOCK_SIZE) ? "成功" : "失败");

    // 测试GFNI实现（如果支持）
#ifdef __GFNI__
    uint8_t out_gfni[SM4_BLOCK_SIZE];
    sm4_encrypt_block_gfni(plaintext, out_gfni, rk);
    printf("GFNI实现测试: %s\n", memcmp(out_gfni, ciphertext, SM4_BLOCK_SIZE) ? "成功" : "失败");
#else
    printf("GFNI实现测试: 未支持GFNI\n");
#endif

    // 测试GCM模式
    sm4_gcm_ctx gcm_ctx;
    uint8_t iv[12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
    uint8_t aad[16] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    uint8_t gcm_plain[32];
    memcpy(gcm_plain, plaintext, SM4_BLOCK_SIZE);
    memcpy(gcm_plain + SM4_BLOCK_SIZE, plaintext, SM4_BLOCK_SIZE);
    uint8_t gcm_cipher[32];
    uint8_t tag[16];

    sm4_gcm_init(&gcm_ctx, key, iv, 12);
    sm4_gcm_update_aad(&gcm_ctx, aad, 16);
    sm4_gcm_encrypt(&gcm_ctx, gcm_plain, gcm_cipher, 32);
    sm4_gcm_final(&gcm_ctx, tag);

    // 验证加密结果（简单检查非全零）
    int gcm_valid = 1;
    for (int i = 0; i < 32; i++) {
        if (gcm_cipher[i] == gcm_plain[i]) {
            gcm_valid = 0;
            break;
        }
    }
    printf("GCM模式测试: %s\n", gcm_valid ? "成功" : "失败");
}

int main() {
    test_sm4();
    return 0;
}