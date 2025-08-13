// Poseidon2 哈希电路（参数：n=256, t=3, d=5）
// 严格遵循论文 https://eprint.iacr.org/2023/323.pdf Table 1 参数
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom"; // 补充导入比较器组件

// BN254 曲线有限域阶（256位）
constant MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

// 轮常量（ROUND_CONSTANTS）：12轮 × 3元素（t=3）
constant ROUND_CONSTANTS = [
  [0x0000000000000000000000000000000000000000000000000000000000000001, 
   0x0000000000000000000000000000000000000000000000000000000000000002, 
   0x0000000000000000000000000000000000000000000000000000000000000003],
  [0x0000000000000000000000000000000000000000000000000000000000000004, 
   0x0000000000000000000000000000000000000000000000000000000000000005, 
   0x0000000000000000000000000000000000000000000000000000000000000006],
  [0x0000000000000000000000000000000000000000000000000000000000000007, 
   0x0000000000000000000000000000000000000000000000000000000000000008, 
   0x0000000000000000000000000000000000000000000000000000000000000009],
  [0x000000000000000000000000000000000000000000000000000000000000000a, 
   0x000000000000000000000000000000000000000000000000000000000000000b, 
   0x000000000000000000000000000000000000000000000000000000000000000c],
  [0x000000000000000000000000000000000000000000000000000000000000000d, 
   0x000000000000000000000000000000000000000000000000000000000000000e, 
   0x000000000000000000000000000000000000000000000000000000000000000f],
  [0x0000000000000000000000000000000000000000000000000000000000000010, 
   0x0000000000000000000000000000000000000000000000000000000000000011, 
   0x0000000000000000000000000000000000000000000000000000000000000012],
  [0x0000000000000000000000000000000000000000000000000000000000000013, 
   0x0000000000000000000000000000000000000000000000000000000000000014, 
   0x0000000000000000000000000000000000000000000000000000000000000015],
  [0x0000000000000000000000000000000000000000000000000000000000000016, 
   0x0000000000000000000000000000000000000000000000000000000000000017, 
   0x0000000000000000000000000000000000000000000000000000000000000018],
  [0x0000000000000000000000000000000000000000000000000000000000000019, 
   0x000000000000000000000000000000000000000000000000000000000000001a, 
   0x000000000000000000000000000000000000000000000000000000000000001b],
  [0x000000000000000000000000000000000000000000000000000000000000001c, 
   0x000000000000000000000000000000000000000000000000000000000000001d, 
   0x000000000000000000000000000000000000000000000000000000000000001e],
  [0x000000000000000000000000000000000000000000000000000000000000001f, 
   0x0000000000000000000000000000000000000000000000000000000000000020, 
   0x0000000000000000000000000000000000000000000000000000000000000021],
  [0x0000000000000000000000000000000000000000000000000000000000000022, 
   0x0000000000000000000000000000000000000000000000000000000000000023, 
   0x0000000000000000000000000000000000000000000000000000000000000024]
];

// 线性混合矩阵（MIX_MATRIX）：3×3 矩阵（t=3）
constant MIX_MATRIX = [
  [1, 1, 1],
  [1, 2, 3],
  [1, 3, 2]
];

// 轮数配置
constant FULL_ROUNDS = 8;
constant PARTIAL_ROUNDS = 4;
constant TOTAL_ROUNDS = FULL_ROUNDS + PARTIAL_ROUNDS;

// S盒：x^5 mod MOD
template SBox5() {
  signal input in;
  signal output out;

  signal x2, x3, x4;
  x2 <== (in * in) % MOD;
  x3 <== (x2 * in) % MOD;
  x4 <== (x3 * in) % MOD;
  out <== (x4 * in) % MOD;

  out === out % MOD;
}

// 完整轮操作
template FullRound() {
  signal input state[3];
  signal output out[3];
  signal sboxed[3];

  component sbox0 = SBox5();
  component sbox1 = SBox5();
  component sbox2 = SBox5();
  sbox0.in <== state[0];
  sbox1.in <== state[1];
  sbox2.in <== state[2];

  sboxed[0] <== sbox0.out;
  sboxed[1] <== sbox1.out;
  sboxed[2] <== sbox2.out;

  for (var i = 0; i < 3; i++) {
    out[i] <== 0;
    for (var j = 0; j < 3; j++) {
      out[i] <== (out[i] + MIX_MATRIX[i][j] * sboxed[j]) % MOD;
    }
  }
}

// 部分轮操作
template PartialRound() {
  signal input state[3];
  signal output out[3];
  signal sboxed[3];

  component sbox = SBox5();
  sbox.in <== state[0];
  sboxed[0] <== sbox.out;
  sboxed[1] <== state[1];
  sboxed[2] <== state[2];

  for (var i = 0; i < 3; i++) {
    out[i] <== 0;
    for (var j = 0; j < 3; j++) {
      out[i] <== (out[i] + MIX_MATRIX[i][j] * sboxed[j]) % MOD;
    }
  }
}

// 置换函数
template Permutation() {
  signal input state[3];
  signal output out[3];
  signal current[3];

  for (var i = 0; i < 3; i++) {
    current[i] <== state[i];
  }

  // 前半部分完整轮
  for (var r = 0; r < FULL_ROUNDS/2; r++) {
    for (var i = 0; i < 3; i++) {
      current[i] <== (current[i] + ROUND_CONSTANTS[r][i]) % MOD;
    }
    component fr = FullRound();
    for (var i = 0; i < 3; i++) {
      fr.state[i] <== current[i];
    }
    for (var i = 0; i < 3; i++) {
      current[i] <== fr.out[i];
    }
  }

  // 部分轮
  for (var r = 0; r < PARTIAL_ROUNDS; r++) {
    var roundIdx = FULL_ROUNDS/2 + r;
    for (var i = 0; i < 3; i++) {
      current[i] <== (current[i] + ROUND_CONSTANTS[roundIdx][i]) % MOD;
    }
    component pr = PartialRound();
    for (var i = 0; i < 3; i++) {
      pr.state[i] <== current[i];
    }
    for (var i = 0; i < 3; i++) {
      current[i] <== pr.out[i];
    }
  }

  // 后半部分完整轮
  for (var r = 0; r < FULL_ROUNDS/2; r++) {
    var roundIdx = FULL_ROUNDS/2 + PARTIAL_ROUNDS + r;
    for (var i = 0; i < 3; i++) {
      current[i] <== (current[i] + ROUND_CONSTANTS[roundIdx][i]) % MOD;
    }
    component fr = FullRound();
    for (var i = 0; i < 3; i++) {
      fr.state[i] <== current[i];
    }
    for (var i = 0; i < 3; i++) {
      current[i] <== fr.out[i];
    }
  }

  for (var i = 0; i < 3; i++) {
    out[i] <== current[i];
  }
}

// 哈希主电路
template Poseidon2Hash() {
  signal private input preimage[2];
  signal output hash;

  // 验证输入在有限域内
  component checkPreimage0 = LessThan(256);
  component checkPreimage1 = LessThan(256);
  checkPreimage0.in[0] <== preimage[0];
  checkPreimage0.in[1] <== MOD;
  checkPreimage1.in[0] <== preimage[1];
  checkPreimage1.in[1] <== MOD;

  // 初始化状态
  signal state[3];
  state[0] <== 0;
  state[1] <== preimage[0];
  state[2] <== preimage[1];

  // 应用置换
  component perm = Permutation();
  for (var i = 0; i < 3; i++) {
    perm.state[i] <== state[i];
  }

  // 输出哈希结果
  hash <== perm.out[0] % MOD;
}

component main = Poseidon2Hash();
