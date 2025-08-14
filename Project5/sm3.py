# SM3密码杂凑算法实现
# 功能：实现对输入字节流的哈希计算，输出256位哈希值，用于SM2签名中的消息摘要计算

# 初始向量IV：SM3算法规定的初始哈希值
_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
)

# 常量数组T：前16轮使用0x79CC4519，后48轮使用0x7A879D8A
_T = [0x79CC4519] * 16 + [0x7A879D8A] * 48


def _rotl(x: int, n: int) -> int:
    """
    循环左移函数
    :param x: 输入32位整数
    :param n: 移位位数（对32取模，避免溢出）
    :return: 左移后的32位整数
    """
    n = n % 32  # 确保移位不超过32位
    # 左移n位后与右移(32-n)位的结果拼接，再取低32位
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _P0(x: int) -> int:
    """
    置换函数P0：用于消息扩展和压缩过程
    公式：P0(x) = x ^ (x << 9) ^ (x << 17)（均为循环左移）
    """
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _P1(x: int) -> int:
    """
    置换函数P1：用于消息扩展
    公式：P1(x) = x ^ (x << 15) ^ (x << 23)（均为循环左移）
    """
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _FF(j: int, x: int, y: int, z: int) -> int:
    """
    布尔函数FF：根据轮数j选择不同的运算
    - 当j ∈ [0,15]时，FF(j,x,y,z) = x ^ y ^ z
    - 当j ∈ [16,63]时，FF(j,x,y,z) = (x & y) | (x & z) | (y & z)
    """
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _GG(j: int, x: int, y: int, z: int) -> int:
    """
    布尔函数GG：根据轮数j选择不同的运算
    - 当j ∈ [0,15]时，GG(j,x,y,z) = x ^ y ^ z
    - 当j ∈ [16,63]时，GG(j,x,y,z) = (x & y) | (~x & z)
    """
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (~x & z) & 0xffffffff  # 确保结果为32位


def _compress(v, b: bytes):
    """
    压缩函数：对512位消息块进行压缩，更新哈希值
    :param v: 当前哈希值（8个32位整数）
    :param b: 512位消息块（64字节）
    :return: 压缩后的哈希值
    """
    # 消息扩展：生成68个字W和64个字W'
    W = [0] * 68  # W[0..67]
    W_ = [0] * 64  # W'[0..63]

    # 前16个W直接从消息块中取（大端字节序）
    for i in range(16):
        W[i] = int.from_bytes(b[4*i:4*(i+1)], 'big')

    # 后52个W通过扩展公式计算
    for i in range(16, 68):
        W[i] = (_P1(W[i-16] ^ W[i-9] ^ _rotl(W[i-3], 15)) 
                ^ _rotl(W[i-13], 7) 
                ^ W[i-6]) & 0xffffffff

    # 生成W'
    for i in range(64):
        W_[i] = (W[i] ^ W[i+4]) & 0xffffffff

    # 初始化压缩寄存器
    A, B, C, D, E, F, G, H = v

    # 64轮压缩运算
    for j in range(64):
        # 计算中间变量
        SS1 = _rotl((_rotl(A, 12) + E + _rotl(_T[j], j)) & 0xffffffff, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (_FF(j, A, B, C) + D + SS2 + W_[j]) & 0xffffffff
        TT2 = (_GG(j, E, F, G) + H + SS1 + W[j]) & 0xffffffff

        # 更新寄存器
        D = C
        C = _rotl(B, 9)
        B = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _P0(TT2)

    # 与初始哈希值异或，得到压缩结果
    return [(x ^ y) & 0xffffffff for x, y in zip(v, [A, B, C, D, E, F, G, H])]


class SM3:
    """SM3哈希算法类：支持增量更新数据并计算哈希值"""
    def __init__(self, data: bytes = b''):
        self._v = list(_IV)  # 当前哈希值（初始为IV）
        self._buf = b''      # 未处理的字节缓冲区
        self._len = 0        # 总数据长度（字节）
        if data:
            self.update(data)

    def update(self, data: bytes):
        """增量更新数据：处理输入字节流，积累到缓冲区并批量压缩"""
        self._len += len(data)
        data = self._buf + data  # 拼接缓冲区数据
        off = 0
        # 每次处理64字节（512位）的块
        while off + 64 <= len(data):
            blk = data[off:off+64]
            self._v = _compress(self._v, blk)  # 压缩当前块
            off += 64
        self._buf = data[off:]  # 剩余数据存入缓冲区

    def digest(self) -> bytes:
        """计算最终哈希值：对剩余数据进行填充后压缩"""
        # 填充规则：
        # 1. 补一个0x80，然后补0x00直到长度≡56 mod 64
        # 2. 最后8字节存储总长度（比特数，大端）
        bitlen = self._len * 8  # 总长度（比特）
        pad = (b'\x80' 
               + b'\x00' * ((56 - (self._len + 1) % 64) % 64) 
               + bitlen.to_bytes(8, 'big'))

        # 处理填充后的数据
        v = list(self._v)
        data = self._buf + pad
        for off in range(0, len(data), 64):
            v = _compress(v, data[off:off+64])

        # 拼接8个32位整数为256位哈希值（大端）
        return b''.join(x.to_bytes(4, 'big') for x in v)

    def hexdigest(self) -> str:
        """返回16进制哈希字符串"""
        return self.digest().hex()


def sm3(data: bytes) -> bytes:
    """快捷函数：直接计算输入数据的SM3哈希值"""
    return SM3(data).digest()