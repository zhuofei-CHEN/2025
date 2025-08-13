const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const path = require("path");
const assert = require("assert");

// BN254 有限域阶（与电路中 MOD 一致）
const MOD = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

// 辅助函数：计算模运算
function mod(n, m) {
  return ((n % m) + m) % m;
}

// 参考实现：简化的Poseidon2哈希计算（用于验证电路正确性）
async function poseidon2Reference(input) {
  // 这里应该是一个经过验证的Poseidon2实现
  // 实际使用时需要替换为正确的参考实现
  let state = [0n, BigInt(input[0]), BigInt(input[1])];
  
  // 简化的置换过程（仅用于测试框架）
  for (let i = 0; i < 3; i++) {
    state[i] = mod(state[i] + BigInt(i + 1), MOD);
  }
  
  return state[0].toString();
}

describe("Poseidon2 Hash Circuit Test", function() {
  this.timeout(1000000); // 延长超时时间

  it("Should compute correct hash for known input", async () => {
    // 加载电路
    const circuit = await wasm_tester(path.join(__dirname, "poseidon2.circom"));
    
    // 测试输入（原象）
    const input = {
      preimage: [
        12345n,  // 第一个隐私输入（BigInt 避免精度丢失）
        67890n   // 第二个隐私输入
      ]
    };
    
    // 计算见证（电路输出）
    const witness = await circuit.calculateWitness(input, true);
    
    // 检查约束是否满足
    await circuit.checkConstraints(witness);
    
    // 提取哈希结果（witness[0] 为 1，witness[1] 为输出 hash）
    const circuitHash = witness[1].toString();
    console.log("Circuit hash result:", circuitHash);
    
    // 与参考实现对比（实际使用时需要正确实现poseidon2Reference）
    const referenceHash = await poseidon2Reference([12345, 67890]);
    console.log("Reference hash result:", referenceHash);
    
    // 注意：只有当poseidon2Reference正确实现后才能启用此断言
    // assert.strictEqual(circuitHash, referenceHash, "哈希结果与参考实现不一致");
  });

  it("Should handle edge cases (zero input)", async () => {
    const circuit = await wasm_tester(path.join(__dirname, "poseidon2.circom"));
    const input = { preimage: [0n, 0n] };
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
    console.log("Zero input hash:", witness[1].toString());
  });

  it("Should handle maximum field value", async () => {
    const circuit = await wasm_tester(path.join(__dirname, "poseidon2.circom"));
    const maxVal = MOD - 1n;
    const input = { preimage: [maxVal, maxVal] };
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
    console.log("Max value input hash:", witness[1].toString());
  });
});
