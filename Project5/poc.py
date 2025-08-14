# SM2安全漏洞验证代码（Proof of Concept）
# 功能：验证SM2签名算法在各种误用场景下的安全漏洞，包括：
# 1. 随机数k泄露导致私钥泄露
# 2. 同一用户复用k导致私钥泄露
# 3. 不同用户复用k导致私钥泄露
# 4. 跨算法（ECDSA与SM2）复用k导致私钥泄露
# 5. 验签实现错误导致公钥泄露
# 6. ECDSA签名的代数伪造演示

from sm2 import (
    keygen, sign, verify, ZA, sm3_hash, G, scalar_mul, n, Point, mod_inv,
    recover_d_from_k_sm2, recover_d_from_two_sigs_reuse_k, recover_d_cross_users,
    recover_pub_from_sig_misuse,
    ecdsa_sign_raw, ecdsa_verify_raw
)
import secrets


def poc_leak_k():
    """
    场景1：签名随机数k泄露时，私钥d可被恢复
    步骤：
    1. 生成密钥对(d, P)
    2. 使用已知的k生成签名(r, s)
    3. 用recover_d_from_k_sm2从(r, s, k)恢复d
    4. 验证恢复的d是否与原始d一致
    """
    d, P = keygen()
    ID = b'ALICE'
    M = b'leak k example'
    # 生成已知的随机数k（模拟泄露场景）
    k = secrets.randbelow(n - 1) + 1
    # 手动生成签名（与sign函数逻辑一致）
    e = sm3_hash(ZA(ID, P) + M)
    x1 = (scalar_mul(k, G).x) % n
    r = (e + x1) % n
    s = (mod_inv(1 + d, n) * (k - r * d)) % n
    # 从k和签名恢复d
    d_rec = recover_d_from_k_sm2(r, s, k)
    return {
        "d": d, 
        "recovered": d_rec, 
        "equal": d == d_rec  # 预期为True，证明泄露
    }


def poc_reuse_k_same_user():
    """
    场景2：同一用户对两条消息复用k时，私钥d可被恢复
    步骤：
    1. 生成密钥对(d, P)
    2. 对两条消息M1、M2使用相同k生成签名(s1, r1)、(s2, r2)
    3. 用recover_d_from_two_sigs_reuse_k恢复d
    4. 验证恢复的d是否与原始d一致
    """
    d, P = keygen()
    ID = b'ALICE'
    M1, M2 = b'msg one', b'msg two'
    # 复用的随机数k
    k = secrets.randbelow(n - 1) + 1
    # 对M1生成签名
    e1 = sm3_hash(ZA(ID, P) + M1)
    x1 = (scalar_mul(k, G).x) % n
    r1 = (e1 + x1) % n
    s1 = (mod_inv(1 + d, n) * (k - r1 * d)) % n
    # 对M2生成签名（复用k）
    e2 = sm3_hash(ZA(ID, P) + M2)
    x2 = (scalar_mul(k, G).x) % n  # x2与x1相同（因k相同）
    r2 = (e2 + x2) % n
    s2 = (mod_inv(1 + d, n) * (k - r2 * d)) % n
    # 从两个签名恢复d
    d_rec = recover_d_from_two_sigs_reuse_k(r1, s1, r2, s2)
    return {
        "d": d, 
        "recovered": d_rec, 
        "equal": d == d_rec  # 预期为True，证明泄露
    }


def poc_reuse_k_two_users():
    """
    场景3：不同用户意外复用k时，双方私钥均可被恢复
    步骤：
    1. 生成两个用户的密钥对(dA, PA)、(dB, PB)
    2. 双方对不同消息使用相同k生成签名
    3. 用recover_d_cross_users分别恢复dA和dB
    4. 验证恢复结果
    """
    dA, PA = keygen()  # 用户A的密钥对
    dB, PB = keygen()  # 用户B的密钥对
    IDA, IDB = b'ALICE', b'BOB'
    M1, M2 = b'Alice message', b'Bob message'
    # 双方共用的随机数k
    k = secrets.randbelow(n - 1) + 1
    # 用户A生成签名
    e1 = sm3_hash(ZA(IDA, PA) + M1)
    x = (scalar_mul(k, G).x) % n  # kG的x坐标
    r1 = (e1 + x) % n
    s1 = (mod_inv(1 + dA, n) * (k - r1 * dA)) % n
    # 用户B生成签名（复用k）
    e2 = sm3_hash(ZA(IDB, PB) + M2)
    r2 = (e2 + x) % n  # x与用户A的x相同
    s2 = (mod_inv(1 + dB, n) * (k - r2 * dB)) % n
    # 恢复双方私钥
    dA_rec = recover_d_cross_users(k, r1, s1)
    dB_rec = recover_d_cross_users(k, r2, s2)
    return {
        "A": {"d": dA, "rec": dA_rec, "equal": dA == dA_rec},
        "B": {"d": dB, "rec": dB_rec, "equal": dB == dB_rec},
    }


def poc_reuse_k_ecdsa_sm2():
    """
    场景4：同一私钥d和随机数k分别用于ECDSA和SM2签名时，d可被恢复
    步骤：
    1. 生成密钥对(d, P)
    2. 用k对消息M_ecdsa生成ECDSA签名(s1, r1)
    3. 用k对消息M_sm2生成SM2签名(s2, r2)
    4. 联立两式求解d并验证
    推导：
    ECDSA：s1 = k⁻¹*(e1 + d*r1) → k = (e1 + d*r1)*s1⁻¹
    SM2：s2 = (1+d)⁻¹*(k - d*r2)
    联立消去k，解得：
    d = (s1*s2 - e1) * (r1 - s1*s2 - s1*r2)⁻¹ mod n
    """
    d, P = keygen()
    ID = b'ALICE'
    M_sm2 = b'sm2 message'
    M_ecdsa = b'ecdsa message'
    k = secrets.randbelow(n - 1) + 1  # 共用的k
    # 生成SM2签名
    e2 = sm3_hash(ZA(ID, P) + M_sm2)
    x = (scalar_mul(k, G).x) % n
    r2 = (e2 + x) % n
    s2 = (mod_inv(1 + d, n) * (k - r2 * d)) % n
    # 生成ECDSA签名
    e1 = sm3_hash(M_ecdsa)  # ECDSA的消息哈希
    r1, s1 = ecdsa_sign_raw(d, e1, k)
    # 用公式恢复d
    num = (s1 * s2 - e1) % n
    den = (r1 - (s1 * s2 + s1 * r2) % n) % n
    d_rec = (num * mod_inv(den, n)) % n
    return {
        "d": d, 
        "rec": d_rec, 
        "equal": d_rec == d,  # 预期为True
        "ecdsa": {"r": r1, "s": s1, "e": e1},
        "sm2": {"r": r2, "s": s2, "e": e2}
    }


def poc_recover_pub_from_sig_misuse():
    """
    场景5：验签实现错误（e未绑定公钥）时，公钥可被恢复
    步骤：
    1. 生成密钥对(d, P)
    2. 生成正常签名(r, s)
    3. 模拟攻击者用错误的e计算方式（缺少ZA）恢复公钥
    4. 验证恢复的公钥是否正确
    """
    d, P = keygen()
    ID = b'ALICE'
    M = b'bind ZA wrongly (for demo)'
    # 生成正常签名
    r, s = sign(d, ID, M, deterministic=False)
    # 攻击者用错误逻辑恢复公钥
    cands = recover_pub_from_sig_misuse(ID, M, r, s)
    # 验证哪些候选公钥可通过正常验签
    valid = [C for C in cands if verify(C, ID, M, (r, s))]
    return {
        "trueP": (P.x, P.y),  # 真实公钥
        "candidates": [(c.x, c.y) for c in cands],  # 恢复的候选公钥
        "valid_under_true_verify": [(v.x, v.y) for v in valid]  # 有效的候选
    }


def forge_ecdsa_algebraic_demo():
    """
    场景6：ECDSA签名的代数伪造（仅演示，非针对任意消息）
    原理：通过构造参数使签名验证等式成立，而非用私钥签名
    步骤：
    1. 随机选择u, v ∈ [1, n-1]
    2. 计算R' = uG + vP，r' = x(R') mod n
    3. 构造s' = r' * v⁻¹ mod n，e' = r' * u * v⁻¹ mod n
    4. 验证(r', s')是否为e'的有效签名
    """
    d, P = keygen()  # 目标公钥（攻击者已知）
    while True:
        # 随机选择u和v
        u = secrets.randbelow(n - 1) + 1
        v = secrets.randbelow(n - 1) + 1
        # 计算R' = uG + vP
        R1 = scalar_mul(u, G)
        R2 = scalar_mul(v, P)
        from sm2 import point_add as _add
        Rsum = _add(R1, R2)
        if Rsum.inf:
            continue  # 跳过无穷远点
        r = Rsum.x % n
        if r == 0:
            continue  # r不能为0
        # 构造s和e
        s = (r * mod_inv(v, n)) % n
        if s == 0:
            continue  # s不能为0
        e = (r * u * mod_inv(v, n)) % n
        # 验证伪造的签名是否有效
        ok = ecdsa_verify_raw(P, e, (r, s))
        if ok:
            return {
                "pubkey": (P.x, P.y),
                "constructed": {"e": e, "r": r, "s": s},
                "verify_ok": ok  # 预期为True
            }


def main():
    """运行所有PoC并输出结果"""
    print("== 场景1：k泄露导致私钥泄露 ==")
    print(poc_leak_k())
    print("\n== 场景2：同一用户复用k导致私钥泄露 ==")
    print(poc_reuse_k_same_user())
    print("\n== 场景3：不同用户复用k导致私钥泄露 ==")
    print(poc_reuse_k_two_users())
    print("\n== 场景4：跨算法复用k导致私钥泄露 ==")
    print(poc_reuse_k_ecdsa_sm2())
    print("\n== 场景5：验签错误导致公钥泄露 ==")
    print(poc_recover_pub_from_sig_misuse())
    print("\n== 场景6：ECDSA代数伪造演示 ==")
    print(forge_ecdsa_algebraic_demo())


if __name__ == "__main__":
    main()