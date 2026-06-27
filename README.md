# 易盾滑动验证码绕过

## 加密体系

易盾的加密不是标准 AES，是自研的一套。

核心参数：

- `__SBOX__` - 256 字节自定义 S 盒（hex 字符串）
- `__SEED_KEY__` - `"fd6a43ae25f74398b61c03c83be37449"`（128bit）
- `__ROUND_KEY__` - `"037606da0296055c"`，每 4 个 hex 字符一组操作码 [op_index, arg]

加密流程（调用 `aes(input)`）：

```
1. stringToBytes(input) → 得到字节数组 dataBytes
2. genCrc32(dataBytes) → 算出 CRC32，附加到数据后面
3. padPKCS7(combined) → PKCS7 填充到 64 字节对齐
4. generateIV() → 生成 IV 对：
   - seedBytes = stringToBytes(SEED_KEY)
   - random4 = 4 字节随机数
   - IV = expandKey(seedBytes) ^ expandKey(random4)  再 expandKey
   - 返回 [IV_64bytes, rawIV_4bytes]
5. 按 64 字节分块，CBC 加密每个块：
   - applyRoundKey(block) → XOR IV → shifts(key=prevBlock) → XOR prevBlock → 双 SBOX
6. 输出 = base64EncodePrivate(rawIV + 密文)
```

轮密钥操作码（`applyRoundKey`）：

`__ROUND_KEY__` 每 4 hex 一组，共 4 组操作 [op, arg]：

- 0: noop - 校验 arg+0x100>=0
- 1: xor_const - 每个字节 XOR arg
- 2: add_const - 每个字节 + arg
- 3: xor_inc - 每个字节 XOR arg, arg++
- 4: add_inc - 每个字节 + arg, arg++
- 5: xor_dec - 每个字节 XOR arg, arg--
- 6: add_dec - 每个字节 + arg, arg--

Base64 有两套字母表：

- 公共 Base64（`BASE64_ALPHABET`/`BASE64_PADDING="3"`）- 用于 `xorEncode`
- 私有 Base64（`PRIVATE_B64_ALPHABET`/`PRIVATE_B64_PADDING="7"`）- 用于 `aes` 输出

XOR 编码（`xorEncode(key, data)`）：

```
base64Encode( xors( stringToBytes(data), stringToBytes(key) ) )
```

即 data 和 key 都转成字节数组，循环异或，再用公共 Base64 编码。

## 验证流程

```
1. getconf → 2. get → 3. 图像匹配 → 4. 生成轨迹 → 5. check
```

**Step 1 - getconf**：请求 `/api/v2/getconf`，拿到验证码配置（没什么关键数据）。

**Step 2 - get**：请求 `/api/v3/get`，需要带上 `cb` 参数（aes 加密的 uuid）。响应返回：
```
data.bg[0]   背景图 URL（480x240）
data.front[0] 拼图块 URL（带透明通道）
data.token    本次验证的 token
```

**Step 3 - 图像匹配**：下载 bg 和 front 图片，OpenCV 找缺口位置。

用的多方法投票机制，避免单一方法跑偏：

- `TM_CCOEFF_NORMED` + mask（裁切拼图有效区域）
- Canny 边缘 + `TM_CCOEFF_NORMED`（mask 掉透明区）
- Sobel X 梯度 + `TM_CCOEFF_NORMED`
- `TM_CCORR_NORMED` + mask

四个结果取中位数，偏差超 15px 的当离群值踢掉，剩余再取中位数。

计算滑动距离：`gap_x * 855 / 480 + 微量随机偏移`。

**Step 4 - 生成轨迹**：模拟人类拖动，分四个阶段：

- 加速阶段：a=2+random, 到达 50~60% 距离
- 快速逼近：v=4+random, 到达 88~94% 距离
- 减速微调：v=2.5→0.3 递减, 到达距离-3px
- 精确对准：步进 0.2~0.5px, 到达目标

Y 轴加高斯噪声 + sin 曲线微抖动。每个轨迹点 `[x, y, elapsed_ms, trust]`。

轨迹提交数据结构：

```
d   = aes( sample(xorEncode_points, 50).join(':') )
m   = ""  (jigsaw 类型固定空)
p   = aes( xorEncode(token, position_pct) )
f   = aes( xorEncode(token, 去重后时间戳.join(',')) )
ext = aes( xorEncode(token, mouseDownCounts,traceData.length) )
```

`cb` 参数生成：32 位随机 uuid，在 [1,10,12,13,26,31] 六个位置插入 `"vfnv46"`，然后 aes 加密。