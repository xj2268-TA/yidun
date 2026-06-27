# 易盾滑动拼图验证码 

import json
import math
import random
import re
import struct
import time
import urllib.parse
from io import BytesIO
from typing import List, Tuple, Optional

import cv2
import numpy as np
from PIL import Image
import requests


# 常量参数

__SBOX__ = "a7be3f3933fa8c5fcf86c4b6908b569ba1e26c1a6d7cfbf60ae4b00e074a194dac4b73e7f898541159a39d08183b76eedee3ed341e6685d2357440158394b1ff03a9004cbbb5ca7dcb7f41489a16e03dcc9c71eb3c9796685b1d01b4d56193a6e1f1a2470445c191ae49c5d82765dc82c350f263387a24a502fcbf442e2dddaad0e936d9ea22b89275307b42518fbc3a626ba806d4ecd6d725f50cc8c72fefa4551ccd6fc9b2b7ab954f815c7264c6e51f4eaf99885a79892b1b60a0b3526e57ba5d178d370958847eb9fd28f9ce0bc023f4148a2adfe632126769057043d3bd8eda0df7872629f3809ef05310e83113216afe202c460fc23e789f77d1addb5e"
__SEED_KEY__ = "fd6a43ae25f74398b61c03c83be37449"
__ROUND_KEY__ = "037606da0296055c"

BASE64_ALPHABET = "i/x1XgU0z7k8N+lCpOnPrv6\\qu2Gj9HRcwTYZ4bfSJBhaWstAeoMIEQ5mDdVFLKy"
BASE64_PADDING = "3"
PRIVATE_B64_ALPHABET = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo"
PRIVATE_B64_PADDING = "7"

# cb 生成参数
CB_SUFFIX = "m25b40"
CB_CODE = "vfnv46"
CB_POS = [1, 10, 12, 13, 26, 31]

SAMPLE_NUM = 50

CRC32_TABLE = [
    0x0, 0x77073096, 0xee0e612c, 0x990951ba, 0x76dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0xedb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x9b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x1db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x6b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0xf00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x86d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x3b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x4db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0xd6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0xa00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x26d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x5005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0xcb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0xbdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
]


# 1. 基础工具函数

def to_byte(n: int) -> int:
    # 有符号字节钳制 [-128, 127]
    n = n & 0xFF
    if n > 127:
        return n - 256
    return n


def hex_to_byte(hex_str: str) -> int:
    # 2字符hex → 有符号字节
    return to_byte(int(hex_str, 16))


def hexs_to_bytes(hex_str: str) -> list:
    # hex字符串 → 字节数组(signed)
    return [hex_to_byte(hex_str[i:i + 2]) for i in range(0, len(hex_str), 2)]


def int_to_bytes(n: int) -> list:
    # 32位整数 → 4字节数组(大端序, signed)
    return [
        to_byte((n >> 24) & 0xFF),
        to_byte((n >> 16) & 0xFF),
        to_byte((n >> 8) & 0xFF),
        to_byte(n & 0xFF),
    ]


def string_to_bytes(s: str) -> list:
    # 字符串 → 字节数组 (模拟 encodeURIComponent)
    encoded = urllib.parse.quote(s, safe='')
    result = []
    i = 0
    while i < len(encoded):
        if encoded[i] == '%' and i + 2 < len(encoded):
            result.append(hex_to_byte(encoded[i + 1:i + 3]))
            i += 3
        else:
            result.append(to_byte(ord(encoded[i])))
            i += 1
    return result


def hex_format(b: int) -> str:
    # 单字节 → 2字符小写hex
    b = b & 0xFF
    hex_chars = "0123456789abcdef"
    return hex_chars[(b >> 4) & 0xF] + hex_chars[b & 0xF]


def bytes_to_hex(bytes_arr: list) -> str:
    return "".join(hex_format(b) for b in bytes_arr)


def bytes_to_string(bytes_arr: list) -> str:
    # 字节数组 → 字符串 (模拟 decodeURIComponent)
    parts = []
    for b in bytes_arr:
        parts.append("%")
        parts.append(hex_format(b))
    return urllib.parse.unquote("".join(parts))


def copy_to_bytes(src: list, src_offset: int, dst: list, dst_offset: int, count: int) -> list:
    for i in range(count):
        if src_offset + i < len(src):
            dst[dst_offset + i] = src[src_offset + i]
    return dst


def padding_array_zero(length: int) -> list:
    return [0] * length


def hex_to_bytes_simple(hex_str: str) -> list:
    # hex字符串 → 无符号字节列表 (用于SBOX)
    return [int(hex_str[i:i + 2], 16) for i in range(0, len(hex_str), 2)]


# 预计算 SBOX_BYTES (无符号)
SBOX_BYTES = hex_to_bytes_simple(__SBOX__)


# 2. XOR 函数

def xor_byte(a: int, b: int) -> int:
    return to_byte(to_byte(a) ^ to_byte(b))


def xors(data: list, key: list) -> list:
    # 循环异或: data[i] ^ key[i % len(key)]
    if not key:
        return data[:]
    return [xor_byte(data[i], key[i % len(key)]) for i in range(len(data))]


def xor_encode(key: str, data: str) -> str:
    # xorEncode = base64Encode(xors(stringToBytes(data), stringToBytes(key)))
    data_bytes = string_to_bytes(data)
    key_bytes = string_to_bytes(key)
    return base64_encode(xors(data_bytes, key_bytes))


# 3. CRC32

def gen_crc32(bytes_arr: list) -> str:
    # CRC32 → hex字符串
    crc = 0xFFFFFFFF
    for b in bytes_arr:
        b = b & 0xFF
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ b) & 0xFF]
    crc = crc ^ 0xFFFFFFFF
    return bytes_to_hex(int_to_bytes(crc))


# 4. Base64 编解码

def b64_encode_3to4(chunk: list, alphabet: str, padding: str) -> str:
    # 3字节 → 4 Base64字符
    length = len(chunk)
    b0 = chunk[0]
    b1 = chunk[1] if length > 1 else 0
    b2 = chunk[2] if length > 2 else 0

    if length == 1:
        return (
            alphabet[(b0 >> 2) & 0x3F]
            + alphabet[((b0 << 4) & 0x30) + ((b1 >> 4) & 0xF)]
            + padding + padding
        )
    elif length == 2:
        return (
            alphabet[(b0 >> 2) & 0x3F]
            + alphabet[((b0 << 4) & 0x30) + ((b1 >> 4) & 0xF)]
            + alphabet[((b1 << 2) & 0x3C) + ((b2 >> 6) & 0x3)]
            + padding
        )
    else:
        return (
            alphabet[(b0 >> 2) & 0x3F]
            + alphabet[((b0 << 4) & 0x30) + ((b1 >> 4) & 0xF)]
            + alphabet[((b1 << 2) & 0x3C) + ((b2 >> 6) & 0x3)]
            + alphabet[b2 & 0x3F]
        )


def b64_decode_4to3(indices: list) -> list:
    # 4个Base64索引 → 最多3字节
    length = len(indices)
    result = []
    if length >= 2:
        result.append(to_byte(((indices[0] << 2) & 0xFF) + ((indices[1] >> 4) & 0x3)))
    if length >= 3:
        result.append(to_byte(((indices[1] << 4) & 0xFF) + ((indices[2] >> 2) & 0xF)))
    if length >= 4:
        result.append(to_byte(((indices[2] << 6) & 0xFF) + (indices[3] & 0x3F)))
    return result


def base64_encode_core(bytes_arr: list, alphabet: str, padding: str) -> str:
    # Base64编码核心
    if not bytes_arr:
        return ""
    # 转为无符号
    unsigned = [b & 0xFF for b in bytes_arr]
    result = []
    i = 0
    while i < len(unsigned):
        if i + 3 <= len(unsigned):
            result.append(b64_encode_3to4(unsigned[i:i + 3], alphabet, padding))
            i += 3
        else:
            result.append(b64_encode_3to4(unsigned[i:], alphabet, padding))
            break
    return "".join(result)


def base64_decode_core(b64_str: str, alphabet: str, padding: str) -> list:
    # Base64解码核心
    padding_idx = b64_str.find(padding)
    chars_str = b64_str[:padding_idx] if padding_idx != -1 else b64_str
    indices = [alphabet.index(c) for c in chars_str]

    result = []
    i = 0
    while i < len(indices):
        if i + 4 <= len(indices):
            result.extend(b64_decode_4to3(indices[i:i + 4]))
            i += 4
        else:
            result.extend(b64_decode_4to3(indices[i:]))
            break
    return result


def base64_encode(bytes_arr: list) -> str:
    # 公共Base64编码 (用于xorEncode)
    return base64_encode_core(bytes_arr, BASE64_ALPHABET, BASE64_PADDING)


def base64_encode_private(bytes_arr: list, alphabet: str = None, padding: str = None) -> str:
    # 私有Base64编码 (用于aes输出)
    return base64_encode_core(
        bytes_arr,
        alphabet or PRIVATE_B64_ALPHABET,
        padding or PRIVATE_B64_PADDING
    )


def base64_decode(b64_str: str) -> list:
    # 公共Base64解码
    return base64_decode_core(b64_str, BASE64_ALPHABET, BASE64_PADDING)


# 5. AES 核心

def sub_bytes(block: list) -> list:
    # S盒替换
    return [to_byte(SBOX_BYTES[16 * ((b >> 4) & 0xF) + (b & 0xF)]) for b in block]


def shift_add(a: int, b: int) -> int:
    return to_byte(a + b)


def shifts(data: list, key: list) -> list:
    # 循环相加
    if not key:
        return data[:]
    return [shift_add(data[i], key[i % len(key)]) for i in range(len(data))]


def apply_round_key(block: list) -> list:
    # 自定义轮密钥操作
    rk = __ROUND_KEY__
    i = 0
    while i < len(rk):
        op_idx = hex_to_byte(rk[i:i + 2])
        arg = hex_to_byte(rk[i + 2:i + 4])

        if op_idx == 0:  # noop - 条件检查
            if arg + 0x100 < 0:
                return []
        elif op_idx == 1:  # xor_const
            block = [xor_byte(v, arg) for v in block] if block else []
        elif op_idx == 2:  # add_const
            block = [shift_add(v, arg) for v in block] if block else []
        elif op_idx == 3:  # xor_inc
            new_block = []
            for v in block:
                new_block.append(xor_byte(v, arg))
                arg = to_byte(arg + 1)
            block = new_block
        elif op_idx == 4:  # add_inc
            new_block = []
            for v in block:
                new_block.append(shift_add(v, arg))
                arg = to_byte(arg + 1)
            block = new_block
        elif op_idx == 5:  # xor_dec
            new_block = []
            for v in block:
                new_block.append(xor_byte(v, arg))
                arg = to_byte(arg - 1)
            block = new_block
        elif op_idx == 6:  # add_dec
            new_block = []
            for v in block:
                new_block.append(shift_add(v, arg))
                arg = to_byte(arg - 1)
            block = new_block
        i += 4
    return block


def generate_random_iv() -> list:
    # 生成4字节随机IV
    return [to_byte(random.randint(0, 255)) for _ in range(4)]


def expand_key(key_bytes: list) -> list:
    # 密钥扩展到64字节
    if not key_bytes:
        return padding_array_zero(64)
    if len(key_bytes) >= 64:
        return key_bytes[:64]
    return [key_bytes[i % len(key_bytes)] for i in range(64)]


def pad_pkcs7(data: list) -> list:
    # PKCS7填充到64字节对齐
    if not data:
        return padding_array_zero(64)
    data_len = len(data)
    padding_len = (64 - (data_len % 64) - 4) if (data_len % 64) <= 60 else (128 - (data_len % 64) - 4)
    padded = [0] * (data_len + padding_len + 4)
    copy_to_bytes(data, 0, padded, 0, data_len)
    copy_to_bytes(int_to_bytes(data_len), 0, padded, data_len + padding_len, 4)
    return padded


def blocks_from_bytes(bytes_arr: list) -> list:
    # 切分为64字节块
    if len(bytes_arr) % 64 != 0:
        return []
    return [bytes_arr[i * 64:(i + 1) * 64] for i in range(len(bytes_arr) // 64)]


def generate_iv() -> Tuple[list, list]:
    # 生成IV对: [expanded_iv, raw_iv]
    seed_bytes = string_to_bytes(__SEED_KEY__)
    random_bytes = generate_random_iv()
    seed_bytes = expand_key(seed_bytes)
    seed_bytes = xors(seed_bytes, expand_key(random_bytes))
    seed_bytes = expand_key(seed_bytes)
    return seed_bytes, random_bytes


def aes(input_str: str) -> str:
    # 自定义AES加密 (CBC模式, 64字节块)
    # 流程: stringToBytes → CRC32附加 → PKCS7填充(64B) → 生成IV → CBC加密 → base64EncodePrivate
    data_bytes = string_to_bytes(input_str)
    iv, raw_iv = generate_iv()

    crc_bytes = string_to_bytes(gen_crc32(data_bytes))
    combined = data_bytes[:] + crc_bytes[:]
    padded = pad_pkcs7(combined)
    blocks = blocks_from_bytes(padded)

    result = raw_iv[:]  # 结果以原始IV(4字节)开头
    # 预分配结果数组: 4 + (块数 * 64)
    result.extend([0] * (len(blocks) * 64))
    prev_block = iv[:]  # CBC前一个块(64字节)

    for i, block in enumerate(blocks):
        block = xors(apply_round_key(block), iv)
        block = shifts(block, prev_block)
        block = xors(block, prev_block)
        prev_block = sub_bytes(sub_bytes(block))
        copy_to_bytes(prev_block, 0, result, 64 * i + 4, 64)

    return base64_encode_private(result)


# 6. 工具函数

def sample_arr(arr: list, target_len: int) -> list:
    # 等间隔采样
    n = len(arr)
    if n <= target_len:
        return arr
    result = []
    for i in range(n):
        if i >= (len(result) * (n - 1)) / (target_len - 1):
            result.append(arr[i])
    return result


def unique_2d_array(arr: list, col_idx: int = 0) -> list:
    # 按指定列去重
    seen = set()
    result = []
    for row in arr:
        key = row[col_idx] if col_idx < len(row) else None
        if key is not None and key not in seen:
            seen.add(key)
            result.append(row)
    return result


def generate_uuid(length: int = 32) -> str:
    # 生成随机字符串
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(random.choice(chars) for _ in range(length))


# 7. cb 参数生成

def generate_cb() -> str:
    # 生成 cb 参数: uuid(32) → 在指定位置插入code字符 → AES加密
    rand_str = generate_uuid(32)
    chars = list(rand_str)
    for i, pos in enumerate(CB_POS):
        if pos < len(chars):
            chars[pos] = CB_CODE[i]
    modified = "".join(chars)
    return aes(modified)


# 8. 滑块轨迹编码

def encode_trace_point(token: str, x: float, y: float, t: int, trust: int) -> str:
    # 编码单个轨迹点: xorEncode(token, "x,y,t,trust")
    return xor_encode(token, f"{round(x)},{round(y)},{t},{trust}")


def build_slider_data(
    token: str,
    trace_points: List[Tuple[float, float, int, int]],
    slider_left: float,
    slider_width: float,
    mouse_down_counts: int = 1,
) -> dict:
    # 构建滑块验证提交数据
    # token: 验证码token (来自 /api/v3/get 响应)
    # trace_points: 轨迹点列表 [(x, y, t, trust), ...]
    # slider_left: 滑块终止左边距(px)
    # slider_width: 滑块轨道宽度(px)
    # mouse_down_counts: 鼠标按下次数
    # 返回: {d, m, p, f, ext} 提交数据

    # 对每个轨迹点编码
    trace_data = [xor_encode(token, f"{round(p[0])},{round(p[1])},{p[2]},{p[3]}") for p in trace_points]

    # 去重时间戳
    atom_trace_data = unique_2d_array(trace_points, 2)
    timestamps = sorted(set(p[2] for p in atom_trace_data))

    # 滑块位置百分比 - JS: parseInt(left) / width * 100 (保留全部精度, 不取整!)
    position_pct = int(slider_left) / slider_width * 100

    return {
        "d": aes(":".join(sample_arr(trace_data, SAMPLE_NUM))),
        "m": "",
        "p": aes(xor_encode(token, str(position_pct))),
        "f": aes(xor_encode(token, ",".join(str(t) for t in timestamps))),
        "ext": aes(xor_encode(token, f"{mouse_down_counts},{len(trace_data)}")),
    }


# 9. 轨迹生成

def generate_track(distance: float, duration_ms: int = 800) -> List[Tuple[float, float, int, int]]:
    # 生成模拟人类拖动的轨迹
    # 返回: [(x, y, elapsed_ms, trust), ...]
    points = []
    current = 0.0
    elapsed = 0

    # 加速阶段
    mid = distance * random.uniform(0.50, 0.60)
    while current < mid:
        a = 2.0 + random.uniform(0, 3.0) * (current / max(mid, 1))
        current += a + random.uniform(0, 1)
        if current >= mid:
            current = mid
        y = random.gauss(0, 0.8) + math.sin(current / 25) * 2
        elapsed += random.randint(6, 12)
        points.append((current, y, elapsed, 1))

    # 快速逼近阶段
    fast = distance * random.uniform(0.88, 0.94)
    while current < fast:
        v = 4.0 + random.uniform(0, 4) * (1 - (current - mid) / max(fast - mid, 1))
        current += v + random.uniform(-0.3, 0.8)
        if current >= fast:
            current = fast
        y = random.gauss(0, 0.6) + math.sin(current / 18) * 1.2
        elapsed += random.randint(7, 14)
        points.append((current, y, elapsed, 1))

    # 减速微调
    while current < distance - 3:
        v = max(0.3, 2.5 * (distance - current) / max(distance, 1))
        current += v + random.uniform(-0.3, 0.2)
        if current >= distance - 3:
            current = distance - 3
        y = random.gauss(0, 0.5) + math.sin(current / 12) * 1.0
        elapsed += random.randint(15, 30)
        points.append((current, y, elapsed, 1))

    # 精确对准
    while current < distance:
        current += random.uniform(0.2, 0.5)
        if current > distance:
            current = distance
        y = random.gauss(0, 0.3)
        elapsed += random.randint(20, 45)
        points.append((current, y, elapsed, 1))

    if points[-1][0] != distance:
        elapsed += random.randint(5, 10)
        points.append((distance, 0, elapsed, 1))

    return points


# 10. 图像匹配 (OpenCV)

def url_to_cv2(url: str) -> np.ndarray:
    # 下载图片并转为OpenCV BGR格式
    resp = requests.get(url, timeout=15,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
    resp.raise_for_status()
    img = Image.open(BytesIO(resp.content))
    if img.mode == "RGBA":
        return cv2.cvtColor(np.array(img), cv2.COLOR_RGBA2BGRA)
    else:
        return cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2BGR)


def find_gap_position(bg: np.ndarray, front: np.ndarray) -> float:
    # 边缘形状匹配 + 多方法投票找缺口位置
    # 策略: 提取拼图边缘特征 → 多方法匹配 → 投票+离群值剔除
    front_rgb = front[:, :, :3]
    alpha = front[:, :, 3]
    _, mask = cv2.threshold(alpha, 50, 255, cv2.THRESH_BINARY)

    # 拼图非透明区域轮廓
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if contours:
        x_ct, y_ct, w_ct, h_ct = cv2.boundingRect(contours[0])
        # 拼图有效区域: 从x_ct到x_ct+w_ct, 上下有空白
    else:
        x_ct, w_ct = 0, front.shape[1]

    # 裁掉拼图上下空白, 提取拼图有效区域的RGB和mask
    front_crop = front_rgb[y_ct:y_ct + h_ct, x_ct:x_ct + w_ct]
    mask_crop = mask[y_ct:y_ct + h_ct, x_ct:x_ct + w_ct]

    results = []

    # 方法1: 裁切后的CCOEFF+mask匹配
    r = cv2.matchTemplate(bg, front_crop, cv2.TM_CCOEFF_NORMED, mask=mask_crop)
    _, v1, _, loc1 = cv2.minMaxLoc(r)
    results.append(("CCOEFF_crop", loc1[0] + x_ct, v1))

    # 方法2: 边缘形状匹配 (Sobel梯度+X方向)
    bg_gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    fg_gray = cv2.cvtColor(front_rgb, cv2.COLOR_BGR2GRAY)

    # Sobel X梯度 (检测垂直边缘)
    bg_sobel_x = cv2.Sobel(bg_gray, cv2.CV_64F, 1, 0, ksize=3)
    bg_sobel_x = np.abs(bg_sobel_x).astype(np.uint8)
    fg_sobel_x = cv2.Sobel(fg_gray, cv2.CV_64F, 1, 0, ksize=3)
    fg_sobel_x = np.abs(fg_sobel_x).astype(np.uint8)

    # Canny边缘
    bg_canny = cv2.Canny(bg_gray, 50, 150)
    fg_canny = cv2.Canny(fg_gray, 50, 150)

    # 拼图边缘 mask (只用非透明区域的canny边缘)
    mask_eroded = cv2.erode(mask, np.ones((3, 3), np.uint8), iterations=1)
    fg_canny_masked = cv2.bitwise_and(fg_canny, fg_canny, mask=mask_eroded)

    # Canny匹配
    r = cv2.matchTemplate(bg_canny, fg_canny_masked, cv2.TM_CCOEFF_NORMED)
    _, v2, _, loc2 = cv2.minMaxLoc(r)
    results.append(("Canny", loc2[0], v2))

    # 方法3: Sobel梯度匹配 (更鲁棒)
    r = cv2.matchTemplate(bg_sobel_x, fg_sobel_x, cv2.TM_CCOEFF_NORMED, mask=mask)
    _, v3, _, loc3 = cv2.minMaxLoc(r)
    results.append(("Sobel", loc3[0], v3))

    # 方法4: CCORR+mask
    r = cv2.matchTemplate(bg, front_rgb, cv2.TM_CCORR_NORMED, mask=mask)
    _, v4, _, loc4 = cv2.minMaxLoc(r)
    results.append(("CCORR", loc4[0], v4))

    # 投票: 剔除偏差>15的离群值, 取剩余中位数
    xs = [r[1] for r in results]
    median = sorted(xs)[len(xs) // 2]

    # 剔除距中位数>15的
    inliers = [x for x in xs if abs(x - median) <= 15]
    if len(inliers) >= 2:
        final_x = sorted(inliers)[len(inliers) // 2]
    else:
        final_x = median

    return float(final_x)


def find_gap_position_v1(bg: np.ndarray, front: np.ndarray) -> float:
    # 旧版(保留备用): 模板匹配投票
    front_rgb = front[:, :, :3]
    alpha = front[:, :, 3]
    _, mask = cv2.threshold(alpha, 50, 255, cv2.THRESH_BINARY)
    results = []
    r = cv2.matchTemplate(bg, front_rgb, cv2.TM_CCOEFF_NORMED, mask=mask)
    _, v, _, loc = cv2.minMaxLoc(r)
    results.append(loc[0])
    bg_gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    fg_gray = cv2.cvtColor(front_rgb, cv2.COLOR_BGR2GRAY)
    bg_edg = cv2.Canny(bg_gray, 50, 150)
    fg_edg = cv2.Canny(fg_gray, 50, 150)
    mask_e = cv2.erode(mask, np.ones((3, 3), np.uint8), iterations=1)
    fg_edg = cv2.bitwise_and(fg_edg, fg_edg, mask=mask_e)
    r = cv2.matchTemplate(bg_edg, fg_edg, cv2.TM_CCOEFF_NORMED)
    _, v, _, loc = cv2.minMaxLoc(r)
    results.append(loc[0])
    r = cv2.matchTemplate(bg, front_rgb, cv2.TM_CCORR_NORMED, mask=mask)
    _, v, _, loc = cv2.minMaxLoc(r)
    results.append(loc[0])
    return float(sorted(results)[len(results) // 2])


# 11. 主绕过逻辑

API_SERVER = "c.dun.163.com"
CAPTCHA_ID = "eda6d7f57cf54b5d8f9b0ed24e5b6e66"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Referer": "https://dun.163.com/",
}


def get_config(session: requests.Session) -> dict:
    # /api/v2/getconf - 获取配置
    callback = f"__JSONP_{random.randint(10000000, 99999999)}"
    params = {
        "referer": "https://dun.163.com/trial/jigsaw-wap",
        "zoneId": "",
        "id": CAPTCHA_ID,
        "ipv6": "false",
        "runEnv": "10",
        "iv": "5",
        "loadVersion": "2.5.4",
        "callback": f"{callback}_0",
    }
    resp = session.get(f"https://{API_SERVER}/api/v2/getconf", params=params, timeout=15)
    match = re.search(r"\((\{.*\})\)", resp.text)
    if match:
        return json.loads(match.group(1))
    return {}


def get_captcha(session: requests.Session, fp: str = "", ir_token: str = "") -> dict:
    # /api/v3/get - 获取验证码
    callback = f"__JSONP_{random.randint(10000000, 99999999)}"
    cb = generate_cb()
    params = {
        "referer": "https://dun.163.com/trial/jigsaw-wap",
        "zoneId": "CN31",
        "dt": ir_token or "",
        "irToken": ir_token or "",
        "id": CAPTCHA_ID,
        "fp": fp or "",
        "https": "true",
        "type": "",
        "version": "2.28.5",
        "dpr": "1",
        "dev": "1",
        "cb": cb,
        "ipv6": "false",
        "runEnv": "10",
        "group": "",
        "scene": "",
        "lang": "zh-CN",
        "sdkVersion": "",
        "loadVersion": "2.5.4",
        "iv": "4",
        "user": "",
        "width": "855",
        "audio": "false",
        "sizeType": "10",
        "smsVersion": "v3",
        "token": "",
        "callback": f"{callback}_0",
    }
    resp = session.get(f"https://{API_SERVER}/api/v3/get", params=params, timeout=15)
    match = re.search(r"\((\{.*\})\)", resp.text)
    if match:
        return json.loads(match.group(1))
    return {}


def check_captcha(session: requests.Session, token: str, slider_data: dict,
                  zone_id: str = "CN31", ir_token: str = "") -> dict:
    # /api/v3/check - 提交验证
    callback = f"__JSONP_{random.randint(10000000, 99999999)}"
    cb = generate_cb()
    params = {
        "referer": "https://dun.163.com/trial/jigsaw-wap",
        "zoneId": zone_id,
        "dt": ir_token or "",
        "id": CAPTCHA_ID,
        "token": token,
        "data": json.dumps(slider_data, separators=(',', ':'), ensure_ascii=True),
        "width": "855",
        "type": "2",
        "version": "2.28.5",
        "cb": cb,
        "user": "",
        "extraData": "",
        "bf": "0",
        "runEnv": "10",
        "sdkVersion": "",
        "loadVersion": "2.5.4",
        "iv": "4",
        "callback": f"{callback}_0",
    }
    resp = session.get(f"https://{API_SERVER}/api/v3/check", params=params, timeout=15)
    match = re.search(r"\((\{.*\})\)", resp.text)
    if match:
        return json.loads(match.group(1))
    return {}


def solve_captcha(session: requests.Session, max_retries: int = 10) -> Optional[str]:
    # 完整绕过流程, 返回: validate字符串 (成功) 或 None (失败)
    for attempt in range(max_retries):
        print(f"\n{'=' * 50}")
        print(f"第 {attempt + 1}/{max_retries} 次尝试")

        # 1. 获取验证码
        print("[1/4] 获取验证码...")
        captcha_data = get_captcha(session)
        if captcha_data.get("error") != 0:
            print(f"  [失败] API错误: {captcha_data}")
            continue

        data = captcha_data["data"]
        token = data["token"]
        bg_url = data["bg"][0]
        front_url = data["front"][0]
        captcha_type = data.get("type", 2)
        zone_id = data.get("zoneId", "CN31")

        print(f"  token: {token[:20]}...")
        print(f"  type: {captcha_type}")

        # 2. 图像匹配
        print("[2/4] 计算缺口位置...")
        try:
            bg = url_to_cv2(bg_url)
            front = url_to_cv2(front_url)
            gap_x = find_gap_position(bg, front)
            print(f"  背景: {bg.shape}, 拼图: {front.shape}")
            print(f"  缺口x: {gap_x:.1f}px (原始分辨率)")
        except Exception as e:
            print(f"  [失败] 图像处理错误: {e}")
            continue

        # 3. 计算滑动距离 & 构建轨迹
        print("[3/4] 构建轨迹数据...")
        bg_nw = bg.shape[1]  # 背景自然宽度 (480)
        control_w = 855  # 控制栏总宽度

        # sliderLeft = gap_x * 855 / 480 (CSS left = 显示位置)
        slider_distance = gap_x * control_w / bg_nw
        # 微量过校准
        slider_distance += random.uniform(-1, 2)

        print(f"  滑动距离: {slider_distance:.1f}px, p%: {int(slider_distance)/control_w*100:.4f}")

        # 生成轨迹
        trace_points = generate_track(slider_distance, duration_ms=random.randint(600, 1200))
        print(f"  轨迹点数: {len(trace_points)}, 总时长: {trace_points[-1][2]}ms")

        # 构建提交数据
        slider_data = build_slider_data(
            token=token,
            trace_points=trace_points,
            slider_left=slider_distance,
            slider_width=control_w,  # TOTAL control width (for p% calc: left/855*100)
        )
        print(f"  d长度: {len(slider_data['d'])}, p长度: {len(slider_data['p'])}")

        # 4. 提交验证
        print("[4/4] 提交验证...")
        result = check_captcha(session, token, slider_data, zone_id)
        print(f"  响应: error={result.get('error')}, msg={result.get('msg', '')}, "
              f"result={result.get('data', {}).get('result')}")

        if result.get("error") == 0 and result.get("data", {}).get("result"):
            validate = result.get("data", {}).get("validate", "")
            print(f"\n[成功] 验证通过!")
            print(f"  validate: {validate}")
            return validate
        else:
            print(f"  [失败] result={result.get('data', {}).get('result')}, "
                  f"验证不通过")
            # 不sleep, 直接重试

    return None


# 主函数

def main():
    print("  https://dun.163.com/trial/jigsaw-wap")

    session = requests.Session()
    session.headers.update(HEADERS)

    # 直接开始绕过
    validate = solve_captcha(session, max_retries=15)

    if validate:
        print(f"\n[DONE] 绕过成功! validate = {validate}")
    else:
        print("\n[FAIL] 所有尝试均失败")


if __name__ == "__main__":
    main()
