#!/bin/bash

# 步骤1: 编译电路
echo "Compiling circuit..."
circom poseidon2.circom --r1cs --wasm --sym

# 步骤2: 生成powers of tau
echo "Generating powers of tau..."
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v

# 步骤3: 贡献随机数
echo "Contributing to powers of tau..."
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v -e="$(head -c 40 /dev/urandom | xxd -p -c 40)"

# 步骤4: 准备phase 2
echo "Preparing phase 2..."
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

# 步骤5: 生成证明密钥和验证密钥
echo "Generating proving and verification keys..."
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey

# 步骤6: 再次贡献随机数
echo "Contributing to zkey..."
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey --name="Second contribution" -v -e="$(head -c 40 /dev/urandom | xxd -p -c 40)"

# 步骤7: 导出验证密钥
echo "Exporting verification key..."
snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json

# 步骤8: 准备输入文件
echo "Preparing input file..."
echo '{"preimage": [12345, 67890]}' > input.json

# 步骤9: 计算见证
echo "Calculating witness..."
snarkjs wtns calculate poseidon2.wasm input.json witness.wtns

# 步骤10: 生成证明
echo "Generating proof..."
snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json

# 步骤11: 验证证明
echo "Verifying proof..."
snarkjs groth16 verify verification_key.json public.json proof.json

echo "Process completed successfully!"
