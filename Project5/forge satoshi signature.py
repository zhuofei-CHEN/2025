# 伪造中本聪的SM2签名（演示用）
# 原理：通过构造合适的ZA值，使伪造的签名通过验证
# 参考文档：20250714-wen-btc-public.pdf中关于签名伪造的思路

from sm2 import (
    Point, G, n, sm3_hash, scalar_mul, point_add,
    verify, keygen, O
)
import secrets


def forge_satoshi_signature(pa: Point, ida: bytes, message: bytes) -> tuple[int, int]:
    """
    伪造中本聪的SM2签名
    步骤：
    1. 随机选择r和s'（伪造签名的参数）
    2. 计算t = (r + s') mod n
    3. 计算s'G + t*PA，得到x1（用于构造目标e值）
    4. 目标e值为e_target = (r - x1) mod n
    5. 暴力搜索伪造的ZA值，使SM3(ZA || message) ≡ e_target mod n
    6. 验证伪造的签名是否有效
    """
    print("开始伪造中本聪签名...")
    while True:
        # 1. 随机选择r和s'（范围[1, n-1]）
        r = secrets.randbelow(n - 1) + 1
        s_prime = secrets.randbelow(n - 1) + 1
        # 2. 计算t = (r + s') mod n（t=0时无效）
        t = (r + s_prime) % n
        if t == 0:
            continue
        # 3. 计算s'G + t*PA，获取x1坐标
        s_g = scalar_mul(s_prime, G)  # s'G
        t_p = scalar_mul(t, pa)       # t*PA
        x1y1 = point_add(s_g, t_p)    # s'G + t*PA
        if x1y1.is_inf():
            continue  # 结果为无穷远点时无效
        x1 = x1y1.x % n
        # 4. 计算目标e值：e_target = (r - x1) mod n
        e_target = (r - x1) % n
        # 5. 暴力搜索符合条件的伪造ZA（32字节随机数）
        za_fake = None
        for i in range(100000):  # 限制搜索次数，实际概率极低
            za_candidate = secrets.token_bytes(32)  # 伪造的ZA
            # 计算e_candidate = SM3(za_candidate || message) mod n
            e_candidate = sm3_hash(za_candidate + message) % n
            if e_candidate == e_target:
                za_fake = za_candidate
                print(f"找到有效ZA，尝试次数: {i + 1}")
                break
        if za_fake is None:
            print("未找到有效ZA，重试...")
            continue
        # 6. 验证伪造签名是否有效（使用伪造的ZA）
        def verify_with_fake_za():
            e = sm3_hash(za_fake + message) % n
            t_verify = (r + s_prime) % n
            if t_verify == 0:
                return False
            s_g_verify = scalar_mul(s_prime, G)
            t_p_verify = scalar_mul(t_verify, pa)
            x1_verify = point_add(s_g_verify, t_p_verify)
            if x1_verify.is_inf():
                return False
            R = (e + x1_verify.x % n) % n
            return R == r
        if verify_with_fake_za():
            print("签名伪造成功！")
            return (r, s_prime)


def main():
    # 模拟中本聪的密钥对（实际中未知私钥，仅已知公钥）
    print("=== 模拟环境初始化 ===")
    satoshi_d, satoshi_pa = keygen()  # 模拟中本聪的密钥对
    print(f"中本聪公钥 x: 0x{satoshi_pa.x:064x}")
    print(f"中本聪公钥 y: 0x{satoshi_pa.y:064x}")
    # 伪造参数
    ida = b"Satoshi Nakamoto"  # 中本聪的身份标识
    message = b"I am zhongbencong"  # 待伪造签名的消息
    # 执行伪造
    fake_sig = forge_satoshi_signature(satoshi_pa, ida, message)
    r, s = fake_sig
    print(f"\n伪造签名结果:")
    print(f"r: 0x{r:064x}")
    print(f"s: 0x{s:064x}")
    # 验证伪造签名（标准验签会失败，需配合伪造的ZA）
    print("\n=== 签名验证结果 ===")
    is_valid = verify(satoshi_pa, ida, message, fake_sig)
    print(f"标准验证: {'通过' if is_valid else '失败'}")
    print("提示: 标准验证失败，因未使用伪造的ZA值")


if __name__ == "__main__":
    main()