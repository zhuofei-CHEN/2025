# SM2椭圆曲线公钥密码算法实现
# 功能：实现SM2密钥生成、签名、验签，以及安全漏洞验证（私钥泄露场景）

from dataclasses import dataclass
from typing import Tuple, Optional, List
from sm3 import sm3
import hmac, hashlib, secrets

# ------------------ 曲线参数 ------------------
# SM2推荐的256位椭圆曲线参数（素域F_q）
q = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3  # 素数模数
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498  # 曲线参数a
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A  # 曲线参数b
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D  # 基点x坐标
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2  # 基点y坐标
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7  # 基点阶
h = 1  # 余因子（h=1表示曲线阶等于n）


# ------------------ 基础数论与点运算 ------------------
def mod_inv(x: int, m: int) -> int:
    """
    模逆计算（扩展欧几里得算法）
    :param x: 待求逆的整数
    :param m: 模数（必须为正整数）
    :return: x在模m下的逆元，即x*inv ≡ 1 mod m
    """
    if x == 0:
        raise ZeroDivisionError("零没有模逆")
    a_, b_ = x % m, m  # 确保a_在[0, m)范围内
    u0, u1 = 1, 0      # 用于计算逆元的系数
    while b_:
        q_ = a_ // b_  # 商
        # 辗转相除：a' = b', b' = a' mod b'
        a_, b_ = b_, a_ - q_ * b_
        # 更新系数：u0 = u1, u1 = u0 - q_*u1
        u0, u1 = u1, u0 - q_ * u1
    return u0 % m  # 确保结果为正


def legendre_symbol(a_: int, p_: int) -> int:
    """
    勒让德符号：判断a是否为模p的二次剩余
    公式：(a|p) ≡ a^((p-1)/2) mod p
    :return: 1（二次剩余）, -1（非二次剩余）, 0（a ≡ 0 mod p）
    """
    return pow(a_ % p_, (p_ - 1) // 2, p_)


def sqrt_mod(a_: int, p_: int) -> Optional[int]:
    """
    Tonelli-Shanks算法：求模素数p的平方根（若存在）
    即找到x使得x² ≡ a mod p
    :return: 平方根x，若不存在则返回None
    """
    a_ %= p_
    if a_ == 0:
        return 0  # 0的平方根是0
    # 特殊情况：p ≡ 3 mod 4时，x = ±a^((p+1)/4) mod p
    if p_ % 4 == 3:
        r = pow(a_, (p_ + 1) // 4, p_)
        if (r * r) % p_ == a_:
            return r
        return None
    # 检查a是否为二次剩余
    if legendre_symbol(a_, p_) != 1:
        return None
    # 分解p-1 = q*2^s
    q_, s = p_ - 1, 0
    while q_ % 2 == 0:
        s += 1
        q_ //= 2
    # 找到非二次剩余z
    z = 2
    while legendre_symbol(z, p_) != p_ - 1:
        z += 1
    c = pow(z, q_, p_)  # c = z^q mod p
    x = pow(a_, (q_ + 1) // 2, p_)  # 初始解
    t = pow(a_, q_, p_)  # t = a^q mod p
    m = s
    # 迭代求解
    while t != 1:
        # 找到最小i使得t^(2^i) ≡ 1
        i, tt = 1, (t * t) % p_
        while tt != 1 and i < m:
            tt = (tt * tt) % p_
            i += 1
        if i == m:
            return None  # 无解决方案
        # 更新参数
        b = pow(c, 1 << (m - i - 1), p_)
        x = (x * b) % p_
        c = (b * b) % p_
        t = (t * c) % p_
        m = i
    return x


@dataclass
class Point:
    """椭圆曲线上的点（仿射坐标）"""
    x: Optional[int]  # x坐标
    y: Optional[int]  # y坐标
    inf: bool = False  # 是否为无穷远点

    def is_inf(self) -> bool:
        return self.inf


# 无穷远点（加法单位元）
O = Point(None, None, True)


def is_on_curve(P: Point) -> bool:
    """验证点P是否在SM2曲线上（满足方程y² = x³ + a x + b mod q）"""
    if P.inf:
        return True  # 无穷远点在曲线上
    # 计算y² - (x³ + a x + b) mod q，结果应为0
    return (P.y * P.y - (P.x ** 3 + a * P.x + b)) % q == 0


def point_add(P: Point, Q: Point) -> Point:
    """
    椭圆曲线点加法：P + Q
    规则：
    - 无穷远点 + P = P
    - 若P = -Q（关于x轴对称），则和为无穷远点
    - 否则按椭圆曲线加法公式计算
    """
    if P.inf:
        return Q
    if Q.inf:
        return P
    # 若x坐标相同
    if P.x == Q.x:
        # 若y坐标相反（P = -Q），返回无穷远点
        if (P.y + Q.y) % q == 0:
            return O
        # 否则为点加倍（P = Q）
        # 斜率l = (3x² + a) / (2y) mod q
        l = (3 * P.x * P.x + a) * mod_inv(2 * P.y % q, q) % q
    else:
        # 斜率l = (y2 - y1)/(x2 - x1) mod q
        l = (Q.y - P.y) * mod_inv((Q.x - P.x) % q, q) % q
    # 计算和点坐标
    x3 = (l * l - P.x - Q.x) % q
    y3 = (l * (P.x - x3) - P.y) % q
    return Point(x3, y3, False)


def scalar_mul(k: int, P: Point) -> Point:
    """
    标量乘法：k*P（将点P累加k次）
    使用快速幂算法（二进制展开）优化计算
    """
    if k % n == 0 or P.inf:
        return O  # 0*P或无穷远点的标量乘为无穷远点
    k = k % n  # 利用阶n简化计算（k = k mod n）
    R = O  # 结果初始为无穷远点
    Qp = P  # 初始为P（即2^0*P）
    # 二进制展开法：遍历k的每一位
    while k:
        if k & 1:
            R = point_add(R, Qp)  # 若当前位为1，累加Qp
        Qp = point_add(Qp, Qp)  # Qp = 2*Qp（左移一位）
        k >>= 1  # 处理下一位
    return R


# 基点G（生成元）
G = Point(Gx, Gy, False)


# ------------------ 辅助函数 ------------------
def _bytes_be(x: int, length: int) -> bytes:
    """将整数x转换为指定长度的大端字节流"""
    return x.to_bytes(length, 'big')


def _int_be(b: bytes) -> int:
    """将大端字节流转换为整数"""
    return int.from_bytes(b, 'big')


def sm3_hash(data: bytes) -> int:
    """计算数据的SM3哈希值并转换为整数"""
    return _int_be(sm3(data))


# ------------------ ZA、KDF与RFC6979 ------------------
def ZA(IDA: bytes, PA: Point) -> bytes:
    """
    计算ZA值：SM2签名中用于绑定用户身份与公钥的哈希值
    公式：ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || xA || yA)
    其中ENTLA为IDA的比特长度（2字节）
    """
    entl = (len(IDA) * 8).to_bytes(2, 'big')  # IDA的比特长度（大端2字节）
    # 拼接数据：ENTLA + IDA + 曲线参数 + 基点 + 公钥
    blob = (
        entl + IDA +
        _bytes_be(a, 32) + _bytes_be(b, 32) +
        _bytes_be(G.x, 32) + _bytes_be(G.y, 32) +
        _bytes_be(PA.x, 32) + _bytes_be(PA.y, 32)
    )
    return sm3(blob)


def kdf(Z: bytes, klen: int) -> bytes:
    """
    密钥派生函数KDF：从共享秘密Z派生出指定长度的密钥
    公式：K = H(Z||ct) || H(Z||ct+1) || ...（截取klen字节）
    其中ct为32位计数器（从1开始）
    """
    ct = 1
    out = b''
    while len(out) < klen:
        # 每次计算SM3(Z || ct)，拼接结果
        out += sm3(Z + ct.to_bytes(4, 'big'))
        ct += 1
    return out[:klen]  # 截取需要的长度


def rfc6979_k(d: int, e_bytes: bytes) -> int:
    """
    RFC6979确定性随机数生成：为签名生成安全的k值
    避免因随机数泄露导致私钥泄露
    此处使用HMAC-SHA256实现（教学用，标准应使用HMAC-SM3）
    """
    V = b'\x01' * 32  # 初始化为全1
    K = b'\x00' * 32  # 初始化为全0
    x = _bytes_be(d, 32)  # 私钥d的32字节表示
    # 第一次HMAC更新
    K = hmac.new(K, V + b'\x00' + x + e_bytes, 'sha256').digest()
    V = hmac.new(K, V, 'sha256').digest()
    # 第二次HMAC更新
    K = hmac.new(K, V + b'\x01' + x + e_bytes, 'sha256').digest()
    V = hmac.new(K, V, 'sha256').digest()
    # 生成足够长度的随机数
    T = b''
    while len(T) < 32:
        V = hmac.new(K, V, 'sha256').digest()
        T += V
    # 转换为[1, n-1]范围内的整数
    return (int.from_bytes(T[:32], 'big') % (n - 1)) + 1


# ------------------ 密钥、签名与验签 ------------------
def keygen() -> Tuple[int, Point]:
    """
    生成SM2密钥对
    :return: (私钥d, 公钥P)，其中P = d*G
    """
    d = secrets.randbelow(n - 1) + 1  # 私钥d ∈ [1, n-1]
    P = scalar_mul(d, G)  # 公钥P = d*G
    return d, P


def sign(d: int, IDA: bytes, M: bytes, deterministic: bool = True) -> Tuple[int, int]:
    """
    SM2签名算法
    :param d: 私钥
    :param IDA: 用户身份标识
    :param M: 待签名消息
    :param deterministic: 是否使用确定性随机数（RFC6979）
    :return: 签名(r, s)
    """
    PA = scalar_mul(d, G)  # 公钥
    ZA_ = ZA(IDA, PA)      # 计算ZA
    e = sm3_hash(ZA_ + M)  # 消息哈希e = SM3(ZA || M)
    while True:
        # 生成随机数k ∈ [1, n-1]
        if deterministic:
            k = rfc6979_k(d, ZA_ + M)  # 确定性k
        else:
            k = secrets.randbelow(n - 1) + 1  # 随机k
        # 计算k*G的x坐标
        x1 = scalar_mul(k, G).x % n
        # 计算r = (e + x1) mod n
        r = (e + x1) % n
        # 检查r是否有效（r≠0且r+k≠n）
        if r == 0 or r + k == n:
            continue
        # 计算s = [(1+d)⁻¹ * (k - r*d)] mod n
        s = (mod_inv(1 + d, n) * (k - r * d)) % n
        # 检查s是否有效（s≠0）
        if s == 0:
            continue
        return r, s


def verify(PA: Point, IDA: bytes, M: bytes, sig: Tuple[int, int]) -> bool:
    """
    SM2验签算法
    :param PA: 公钥
    :param IDA: 用户身份标识
    :param M: 待验证消息
    :param sig: 签名(r, s)
    :return: 验证是否通过
    """
    r, s = sig
    # 检查r和s的范围
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    ZA_ = ZA(IDA, PA)      # 计算ZA
    e = sm3_hash(ZA_ + M)  # 消息哈希e
    t = (r + s) % n        # 计算t = (r + s) mod n
    if t == 0:
        return False       # t=0时无效
    # 计算s*G + t*PA
    x1y1 = point_add(scalar_mul(s, G), scalar_mul(t, PA))
    if x1y1.inf:
        return False       # 结果为无穷远点时无效
    # 计算R = (e + x1) mod n，与r比较
    R = (e + (x1y1.x % n)) % n
    return R == r


# ------------------ 安全漏洞演示：私钥泄露场景 ------------------
def recover_d_from_k_sm2(r: int, s: int, k: int) -> int:
    """
    场景：签名随机数k泄露时，从签名(r,s)恢复私钥d
    推导过程：
    1. 签名公式：s = (1+d)⁻¹ * (k - r*d) mod n
    2. 两边乘(1+d)：s*(1+d) = k - r*d mod n
    3. 整理：s + s*d = k - r*d mod n
    4. 移项：d*(s + r) = k - s mod n
    5. 解得：d = (k - s) * (s + r)⁻¹ mod n
    """
    return ((k - s) % n) * mod_inv((s + r) % n, n) % n


def recover_d_from_two_sigs_reuse_k(r1: int, s1: int, r2: int, s2: int) -> int:
    """
    场景：同一用户对两条消息复用k时，从两个签名恢复d
    推导过程：
    1. 对消息1：s1*(1+d) = k - r1*d mod n
    2. 对消息2：s2*(1+d) = k - r2*d mod n
    3. 两式相减：(s1 - s2)*(1+d) = (r2 - r1)*d mod n
    4. 整理：(s1 - s2) + (s1 - s2)*d = r2*d - r1*d mod n
    5. 移项：d*(s1 - s2 + r1 - r2) = s2 - s1 mod n
    6. 解得：d = (s2 - s1) * (s1 - s2 + r1 - r2)⁻¹ mod n
    """
    num = (s2 - s1) % n
    den = (s1 - s2 + r1 - r2) % n
    return (num * mod_inv(den, n)) % n


def recover_d_cross_users(k: int, r: int, s: int) -> int:
    """
    场景：不同用户意外复用k时，从单个签名恢复对方私钥
    推导同recover_d_from_k_sm2（公式通用）
    """
    return ((k - s) % n) * mod_inv((s + r) % n, n) % n


def recover_pub_from_sig_misuse(IDA: bytes, M: bytes, r: int, s: int) -> List['Point']:
    """
    场景：验签实现错误（未绑定公钥，e计算错误）时，从签名恢复公钥
    错误场景：e被错误计算为SM3(IDA||M)，而非SM3(ZA||M)
    推导过程：
    1. 错误验签中，r = e' + x1 mod n → x1 = r - e' mod n（x1为kG的x坐标）
    2. 签名公式：s*G + r*P = kG - sG → P = (kG - sG) * (s + r)⁻¹
    3. 由x1可求kG的候选点，进而计算公钥P的候选
    """
    e = sm3_hash(IDA + M)  # 错误的e计算（缺少ZA）
    Rx = (r - e) % n       # kG的x坐标候选
    # 求解y² = x³ + a x + b mod q，得到可能的y坐标
    alpha = (pow(Rx, 3, q) + a * Rx + b) % q
    y = sqrt_mod(alpha, q)
    if y is None:
        return []  # 无有效点
    candidates = []
    # 考虑y和q-y两种可能（椭圆曲线点关于x轴对称）
    for yy in (y, (-y) % q):
        R = Point(Rx, yy, False)
        sG = scalar_mul(s, G)
        # 计算P = (R - sG) * (s + r)⁻¹ mod n
        inv = mod_inv((s + r) % n, n)
        R_minus_sG = point_add(R, Point(sG.x, (-sG.y) % q, False))
        P = scalar_mul(inv, R_minus_sG)
        if is_on_curve(P):
            candidates.append(P)
    return candidates


# ------------------ 跨算法复用k的ECDSA实现（用于漏洞演示） ------------------
def ecdsa_sign_raw(d: int, e: int, k: int) -> Tuple[int, int]:
    """
    简化的ECDSA签名（用于演示跨算法复用k的漏洞）
    公式：
    r = x(kG) mod n
    s = k⁻¹*(e + d*r) mod n
    """
    R = scalar_mul(k, G)
    r = R.x % n
    if r == 0:
        raise ValueError("无效k：r=0")
    s = (mod_inv(k, n) * (e + d * r)) % n
    if s == 0:
        raise ValueError("无效k：s=0")
    return r, s


def ecdsa_verify_raw(P: Point, e: int, sig: Tuple[int, int]) -> bool:
    """简化的ECDSA验签"""
    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return False
    w = mod_inv(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    X = point_add(scalar_mul(u1, G), scalar_mul(u2, P))
    if X.inf:
        return False
    return (X.x % n) == r