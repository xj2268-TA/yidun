const safeGlobal = (function () {
    if (typeof window !== 'undefined') return window;
    if (typeof global !== 'undefined') return global;
    return this;
})();

function toByte(n) {
    if (n < -0x80) return toByte(0x100 + n);
    if (n > 0x7f) return toByte(n - 0x100);
    return n;
}

function intToBytes(n) {
    return [
        toByte((n >>> 0x18) & 0xff),
        toByte((n >>> 0x10) & 0xff),
        toByte((n >>> 0x08) & 0xff),
        toByte(n & 0xff)
    ];
}

function hexToByte(hex) {
    hex = '' + hex;
    return toByte(
        (safeGlobal.parseInt(hex.charAt(0), 0x10) << 0x4)
        + safeGlobal.parseInt(hex.charAt(1), 0x10)
    );
}

function hexsToBytes(hex) {
    hex = '' + hex;
    var result = [];
    for (var i = 0, j = 0, n = hex.length / 2; i < n; i++) {
        result[i] = toByte(
            (safeGlobal.parseInt(hex.charAt(j++), 0x10) << 0x4)
            + safeGlobal.parseInt(hex.charAt(j++), 0x10)
        );
    }
    return result;
}

function stringToBytes(str) {
    str = encodeURIComponent(str);
    var result = [];
    for (var i = 0, n = str.length; i < n; i++) {
        if ('%' === str.charAt(i)) {
            if (i + 2 < n)
                result.push(hexToByte('' + str.charAt(++i) + str.charAt(++i)));
        } else {
            result.push(toByte(str.charCodeAt(i)));
        }
    }
    return result;
}

function hexFormat(b) {
    var hexChars = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
    return '' + hexChars[(b >>> 0x4) & 0xf] + hexChars[b & 0xf];
}

function bytesToHex(bytes) {
    return bytes.map(function (b) { return hexFormat(b); }).join('');
}

function bytesToString(bytes) {
    var parts = [];
    for (var i = 0; i < bytes.length; i++) {
        parts.push('%');
        parts.push(hexFormat(bytes[i]));
    }
    return decodeURIComponent(parts.join(''));
}

function paddingArrayZero(len) {
    var result = [];
    for (var i = 0; i < len; i++) result.push(0);
    return result;
}

function copyToBytes(src, srcOffset, dst, dstOffset, count) {
    for (var i = 0; i < count; i++) {
        if (srcOffset + i < src.length)
            dst[dstOffset + i] = src[srcOffset + i];
    }
    return dst;
}

function arrayClone(arr) {
    if (Array.isArray(arr)) {
        var ret = Array(arr.length);
        for (var i = 0; i < arr.length; i++) ret[i] = arr[i];
        return ret;
    }
    return Array.from(arr);
}

function xorByte(a, b) {
    return toByte(toByte(a) ^ toByte(b));
}

function xors(data, key) {
    data = data || [];
    key = key || [];
    var result = [];
    var keyLen = key.length;
    for (var i = 0, n = data.length; i < n; i++) {
        result[i] = xorByte(data[i], key[i % keyLen]);
    }
    return result;
}

function xorEncode(key, data) {
    var dataBytes = stringToBytes(data);
    var keyBytes = stringToBytes(key);
    return base64Encode(xors(dataBytes, keyBytes));
}

function xorDecode(key, encoded) {
    var dataBytes = base64Decode(encoded);
    var keyBytes = stringToBytes(key);
    return bytesToString(xors(dataBytes, keyBytes));
}

var __SBOX__ = "a7be3f3933fa8c5fcf86c4b6908b569ba1e26c1a6d7cfbf60ae4b00e074a194dac4b73e7f898541159a39d08183b76eedee3ed341e6685d2357440158394b1ff03a9004cbbb5ca7dcb7f41489a16e03dcc9c71eb3c9796685b1d01b4d56193a6e1f1a2470445c191ae49c5d82765dc82c350f263387a24a502fcbf442e2dddaad0e936d9ea22b89275307b42518fbc3a626ba806d4ecd6d725f50cc8c72fefa4551ccd6fc9b2b7ab954f815c7264c6e51f4eaf99885a79892b1b60a0b3526e57ba5d178d370958847eb9fd28f9ce0bc023f4148a2adfe632126769057043d3bd8eda0df7872629f3809ef05310e83113216afe202c460fc23e789f77d1addb5e";
var __SEED_KEY__ = "fd6a43ae25f74398b61c03c83be37449";
var __ROUND_KEY__ = "037606da0296055c";

var SBOX_BYTES = hexsToBytes(__SBOX__);

function subBytes(block) {
    return block.map(function (b) {
        return SBOX_BYTES[0x10 * ((b >>> 0x4) & 0xf) + (0xf & b)];
    });
}

function shiftAdd(a, b) { return toByte(a + b); }
function shift(data, arg) { return toByte(data + arg); }

function shifts(data, key) {
    data = data || [];
    key = key || [];
    var result = [];
    var keyLen = key.length;
    for (var i = 0, n = data.length; i < n; i++) {
        result[i] = shift(data[i], key[i % keyLen]);
    }
    return result;
}

function generateRandomIV() {
    var iv = [];
    for (var i = 0; i < 4; i++) {
        iv[i] = toByte(Math.floor(0x100 * Math.random()));
    }
    return iv;
}

function expandKey(keyBytes) {
    if (!keyBytes.length) return paddingArrayZero(0x40);
    if (keyBytes.length >= 0x40) return keyBytes.slice(0, 0x40);
    var expanded = [];
    for (var i = 0; i < 0x40; i++) {
        expanded[i] = keyBytes[i % keyBytes.length];
    }
    return expanded;
}

function padPKCS7(data) {
    if (!data.length) return paddingArrayZero(0x40);
    var padded = [];
    var dataLen = data.length;
    var paddingLen = (dataLen % 0x40) <= 0x3c
        ? 0x40 - (dataLen % 0x40) - 0x4
        : 0x80 - (dataLen % 0x40) - 0x4;
    copyToBytes(data, 0, padded, 0, dataLen);
    for (var i = 0; i < paddingLen; i++) padded[dataLen + i] = 0;
    copyToBytes(intToBytes(dataLen), 0, padded, dataLen + paddingLen, 0x4);
    return padded;
}

function blocksFromBytes(bytes) {
    if (bytes.length % 0x40 !== 0) return [];
    var blocks = [];
    for (var i = 0, blockCount = bytes.length / 0x40; i < blockCount; i++) {
        blocks[i] = [];
        for (var j = 0; j < 0x40; j++) blocks[i][j] = bytes[i * 0x40 + j];
    }
    return blocks;
}

function genCrc32(bytes) {
    var table = [
        0x0,0x77073096,0xee0e612c,0x990951ba,0x76dc419,0x706af48f,0xe963a535,0x9e6495a3,
        0xedb8832,0x79dcb8a4,0xe0d5e91e,0x97d2d988,0x9b64c2b,0x7eb17cbd,0xe7b82d07,0x90bf1d91,
        0x1db71064,0x6ab020f2,0xf3b97148,0x84be41de,0x1adad47d,0x6ddde4eb,0xf4d4b551,0x83d385c7,
        0x136c9856,0x646ba8c0,0xfd62f97a,0x8a65c9ec,0x14015c4f,0x63066cd9,0xfa0f3d63,0x8d080df5,
        0x3b6e20c8,0x4c69105e,0xd56041e4,0xa2677172,0x3c03e4d1,0x4b04d447,0xd20d85fd,0xa50ab56b,
        0x35b5a8fa,0x42b2986c,0xdbbbc9d6,0xacbcf940,0x32d86ce3,0x45df5c75,0xdcd60dcf,0xabd13d59,
        0x26d930ac,0x51de003a,0xc8d75180,0xbfd06116,0x21b4f4b5,0x56b3c423,0xcfba9599,0xb8bda50f,
        0x2802b89e,0x5f058808,0xc60cd9b2,0xb10be924,0x2f6f7c87,0x58684c11,0xc1611dab,0xb6662d3d,
        0x76dc4190,0x1db7106,0x98d220bc,0xefd5102a,0x71b18589,0x6b6b51f,0x9fbfe4a5,0xe8b8d433,
        0x7807c9a2,0xf00f934,0x9609a88e,0xe10e9818,0x7f6a0dbb,0x86d3d2d,0x91646c97,0xe6635c01,
        0x6b6b51f4,0x1c6c6162,0x856530d8,0xf262004e,0x6c0695ed,0x1b01a57b,0x8208f4c1,0xf50fc457,
        0x65b0d9c6,0x12b7e950,0x8bbeb8ea,0xfcb9887c,0x62dd1ddf,0x15da2d49,0x8cd37cf3,0xfbd44c65,
        0x4db26158,0x3ab551ce,0xa3bc0074,0xd4bb30e2,0x4adfa541,0x3dd895d7,0xa4d1c46d,0xd3d6f4fb,
        0x4369e96a,0x346ed9fc,0xad678846,0xda60b8d0,0x44042d73,0x33031de5,0xaa0a4c5f,0xdd0d7cc9,
        0x5005713c,0x270241aa,0xbe0b1010,0xc90c2086,0x5768b525,0x206f85b3,0xb966d409,0xce61e49f,
        0x5edef90e,0x29d9c998,0xb0d09822,0xc7d7a8b4,0x59b33d17,0x2eb40d81,0xb7bd5c3b,0xc0ba6cad,
        0xedb88320,0x9abfb3b6,0x3b6e20c,0x74b1d29a,0xead54739,0x9dd277af,0x4db2615,0x73dc1683,
        0xe3630b12,0x94643b84,0xd6d6a3e,0x7a6a5aa8,0xe40ecf0b,0x9309ff9d,0xa00ae27,0x7d079eb1,
        0xf00f9344,0x8708a3d2,0x1e01f268,0x6906c2fe,0xf762575d,0x806567cb,0x196c3671,0x6e6b06e7,
        0xfed41b76,0x89d32be0,0x10da7a5a,0x67dd4acc,0xf9b9df6f,0x8ebeeff9,0x17b7be43,0x60b08ed5,
        0xd6d6a3e8,0xa1d1937e,0x38d8c2c4,0x4fdff252,0xd1bb67f1,0xa6bc5767,0x3fb506dd,0x48b2364b,
        0xd80d2bda,0xaf0a1b4c,0x36034af6,0x41047a60,0xdf60efc3,0xa867df55,0x316e8eef,0x4669be79,
        0xcb61b38c,0xbc66831a,0x256fd2a0,0x5268e236,0xcc0c7795,0xbb0b4703,0x220216b9,0x5505262f,
        0xc5ba3bbe,0xb2bd0b28,0x2bb45a92,0x5cb36a04,0xc2d7ffa7,0xb5d0cf31,0x2cd99e8b,0x5bdeae1d,
        0x9b64c2b0,0xec63f226,0x756aa39c,0x26d930a,0x9c0906a9,0xeb0e363f,0x72076785,0x5005713,
        0x95bf4a82,0xe2b87a14,0x7bb12bae,0xcb61b38,0x92d28e9b,0xe5d5be0d,0x7cdcefb7,0xbdbdf21,
        0x86d3d2d4,0xf1d4e242,0x68ddb3f8,0x1fda836e,0x81be16cd,0xf6b9265b,0x6fb077e1,0x18b74777,
        0x88085ae6,0xff0f6a70,0x66063bca,0x11010b5c,0x8f659eff,0xf862ae69,0x616bffd3,0x166ccf45,
        0xa00ae278,0xd70dd2ee,0x4e048354,0x3903b3c2,0xa7672661,0xd06016f7,0x4969474d,0x3e6e77db,
        0xaed16a4a,0xd9d65adc,0x40df0b66,0x37d83bf0,0xa9bcae53,0xdebb9ec5,0x47b2cf7f,0x30b5ffe9,
        0xbdbdf21c,0xcabac28a,0x53b39330,0x24b4a3a6,0xbad03605,0xcdd70693,0x54de5729,0x23d967bf,
        0xb3667a2e,0xc4614ab8,0x5d681b02,0x2a6f2b94,0xb40bbe37,0xc30c8ea1,0x5a05df1b,0x2d02ef8d
    ];
    var crc = 0xffffffff;
    for (var i = 0, n = bytes.length; i < n; i++) {
        crc = (crc >>> 0x8) ^ table[0xff & (crc ^ bytes[i])];
    }
    return bytesToHex(intToBytes(0xffffffff ^ crc));
}

var ROUND_KEY_OPS = [
    function noop(block, arg) {
        return (arg + 0x100 >= 0) ? block : [];
    },
    function xorConst(block, arg) {
        arg = toByte(arg);
        if (!block.length) return [];
        return block.map(function (v) { return xorByte(v, arg); });
    },
    function addConst(block, arg) {
        arg = toByte(arg);
        if (!block.length) return [];
        return block.map(function (v) { return shiftAdd(v, arg); });
    },
    function xorInc(block, arg) {
        arg = toByte(arg);
        if (!block.length) return [];
        return block.map(function (v) { return xorByte(v, arg++); });
    },
    function addInc(block, arg) {
        arg = toByte(arg);
        if (!block.length) return [];
        return block.map(function (v) { return shiftAdd(v, arg++); });
    },
    function xorDec(block, arg) {
        arg = toByte(arg);
        if (!block.length) return [];
        return block.map(function (v) { return xorByte(v, arg--); });
    },
    function addDec(block, arg) {
        arg = toByte(arg);
        if (!block.length) return [];
        return block.map(function (v) { return shiftAdd(v, arg--); });
    }
];

function applyRoundKey(block) {
    var rk = __ROUND_KEY__;
    for (var i = 0, n = rk.length; i < n; i += 4) {
        var opIndex = hexToByte(rk.substring(i, i + 2));
        var arg = hexToByte(rk.substring(i + 2, i + 4));
        block = ROUND_KEY_OPS[opIndex](block, arg);
    }
    return block;
}

function aes(input) {
    var dataBytes = stringToBytes(input);
    var ivPair = generateIV();
    var splitPair = splitArray(ivPair, 2);
    var iv = splitPair[0];
    var rawIV = splitPair[1];

    var crcBytes = stringToBytes(genCrc32(dataBytes));
    var combined = arrayClone(dataBytes).concat(arrayClone(crcBytes));
    var padded = padPKCS7(combined);
    var blocks = blocksFromBytes(padded);

    var result = arrayClone(rawIV);
    var prevBlock = iv;

    for (var i = 0, n = blocks.length; i < n; i++) {
        var block = xors(applyRoundKey(blocks[i]), iv);
        block = shifts(block, prevBlock);
        block = xors(block, prevBlock);
        prevBlock = subBytes(subBytes(block));
        copyToBytes(prevBlock, 0, result, 0x40 * i + 0x4, 0x40);
    }
    return base64EncodePrivate(result);
}

function generateIV() {
    var seedBytes = stringToBytes(__SEED_KEY__);
    var randomBytes = generateRandomIV();
    seedBytes = expandKey(seedBytes);
    seedBytes = xors(seedBytes, expandKey(randomBytes));
    seedBytes = expandKey(seedBytes);
    return [seedBytes, randomBytes];
}

function splitArray(arr, n) {
    if (Array.isArray(arr)) return arr;
    if (Symbol.iterator in Object(arr)) {
        var result = [], it = arr[Symbol.iterator](), step;
        while (!(step = it.next()).done) {
            result.push(step.value);
            if (n && result.length === n) break;
        }
        return result;
    }
    throw new TypeError('Invalid attempt to destructure non-iterable instance');
}

var BASE64_ALPHABET = [
    'i','/','x','1','X','g','U','0','z','7','k','8','N','+','l','C',
    'p','O','n','P','r','v','6','\\','q','u','2','G','j','9','H','R',
    'c','w','T','Y','Z','4','b','f','S','J','B','h','a','W','s','t',
    'A','e','o','M','I','E','Q','5','m','D','d','V','F','L','K','y'
];
var BASE64_PADDING = '3';

var PRIVATE_B64_ALPHABET = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo";
var PRIVATE_B64_PADDING = "7";

function b64_encode_3to4(bytes, alphabet, padding) {
    var b0, b1, b2, result = [];
    switch (bytes.length) {
        case 1:
            b0 = bytes[0]; b1 = b2 = 0;
            result.push(
                alphabet[(b0 >>> 0x2) & 0x3f],
                alphabet[((b0 << 0x4) & 0x30) + ((b1 >>> 0x4) & 0xf)],
                padding, padding
            );
            break;
        case 2:
            b0 = bytes[0]; b1 = bytes[1]; b2 = 0;
            result.push(
                alphabet[(b0 >>> 0x2) & 0x3f],
                alphabet[((b0 << 0x4) & 0x30) + ((b1 >>> 0x4) & 0xf)],
                alphabet[((b1 << 0x2) & 0x3c) + ((b2 >>> 0x6) & 0x3)],
                padding
            );
            break;
        case 3:
            b0 = bytes[0]; b1 = bytes[1]; b2 = bytes[2];
            result.push(
                alphabet[(b0 >>> 0x2) & 0x3f],
                alphabet[((b0 << 0x4) & 0x30) + ((b1 >>> 0x4) & 0xf)],
                alphabet[((b1 << 0x2) & 0x3c) + ((b2 >>> 0x6) & 0x3)],
                alphabet[b2 & 0x3f]
            );
            break;
        default:
            return '';
    }
    return result.join('');
}

function b64_decode_4to3(indices, toByteFn) {
    var result = [];
    switch (indices.length) {
        case 2:
            result.push(toByteFn((indices[0] << 0x2 & 0xff) + (indices[1] >>> 0x4 & 0x3)));
            break;
        case 3:
            result.push(toByteFn((indices[0] << 0x2 & 0xff) + (indices[1] >>> 0x4 & 0x3)));
            result.push(toByteFn((indices[1] << 0x4 & 0xff) + (indices[2] >>> 0x2 & 0xf)));
            break;
        case 4:
            result.push(toByteFn((indices[0] << 0x2 & 0xff) + (indices[1] >>> 0x4 & 0x3)));
            result.push(toByteFn((indices[1] << 0x4 & 0xff) + (indices[2] >>> 0x2 & 0xf)));
            result.push(toByteFn((indices[2] << 0x6 & 0xff) + (indices[3] & 0x3f)));
            break;
    }
    return result;
}

function base64EncodeCore(bytes, alphabet, padding) {
    if (!bytes || bytes.length === 0) return '';
    var result = [];
    for (var i = 0; i < bytes.length;) {
        if (i + 3 <= bytes.length) {
            result.push(b64_encode_3to4(bytes.slice(i, i + 3), alphabet, padding));
            i += 3;
        } else {
            result.push(b64_encode_3to4(bytes.slice(i), alphabet, padding));
            break;
        }
    }
    return result.join('');
}

function base64DecodeCore(str, alphabet, padding) {
    var charIndex = function (c) { return alphabet.indexOf(c); };
    var result = [];
    var paddingIdx = str.indexOf(padding);
    var chars = (paddingIdx !== -1 ? str.substring(0, paddingIdx) : str).split('');
    var n = chars.length;
    for (var i = 0; i < n;) {
        if (i + 4 <= n) {
            result = result.concat(b64_decode_4to3(chars.slice(i, i + 4).map(charIndex), toByte));
            i += 4;
        } else {
            result = result.concat(b64_decode_4to3(chars.slice(i).map(charIndex), toByte));
            break;
        }
    }
    return result;
}

function base64Encode(bytes) {
    return base64EncodeCore(bytes, BASE64_ALPHABET, BASE64_PADDING);
}

function base64EncodePrivate(bytes, alphabet, padding) {
    alphabet = alphabet != null ? alphabet : PRIVATE_B64_ALPHABET;
    padding  = padding  != null ? padding  : PRIVATE_B64_PADDING;
    return base64EncodeCore(bytes, alphabet.split(''), padding);
}

function base64Decode(str) {
    return base64DecodeCore(str, BASE64_ALPHABET, BASE64_PADDING);
}

function sample(arr, targetLen) {
    var n = arr.length;
    if (n <= targetLen) return arr;
    var result = [];
    for (var i = 0, j = 0; i < n; i++) {
        if (i >= (j * (n - 1)) / (targetLen - 1)) {
            result.push(arr[i]);
            j++;
        }
    }
    return result;
}

function unique2DArray(arr, colIdx) {
    colIdx = colIdx || 0;
    if (!Array.isArray(arr)) return arr;
    var seen = {};
    var result = [];
    for (var i = 0, n = arr.length; i < n; i++) {
        var key = arr[i][colIdx];
        if (key != null && !seen[key]) {
            seen[key] = true;
            result.push(arr[i]);
        }
    }
    return result;
}

var SAMPLE_NUM = 50;

function encodeTracePoint(token, x, y, t, trust) {
    return xorEncode(token, [Math.round(x), Math.round(y), t, trust].join(','));
}

function buildSliderData(token, tracePoints, sliderLeft, sliderWidth, mouseDownCounts) {
    var traceData = tracePoints.map(function (p) {
        return xorEncode(token, [p[0], p[1], p[2], p[3]].join(','));
    });

    var atomTraceData = unique2DArray(tracePoints, 2);
    var timestamps = atomTraceData.map(function (p) { return p[2]; }).sort(function (a, b) { return a - b; });

    var positionPct = parseInt(sliderLeft, 10) / sliderWidth * 100;

    return {
        d: aes(sample(traceData, SAMPLE_NUM).join(':')),
        m: '',
        p: aes(xorEncode(token, positionPct.toFixed(0))),
        f: aes(xorEncode(token, timestamps.join(','))),
        ext: aes(xorEncode(token, mouseDownCounts + ',' + traceData.length))
    };
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        toByte, hexsToBytes, stringToBytes, bytesToString,
        intToBytes, hexFormat, bytesToHex,
        copyToBytes, paddingArrayZero, arrayClone,

        xorByte, xors, xorEncode, xorDecode,

        aes, subBytes, applyRoundKey, generateIV,
        padPKCS7, blocksFromBytes, expandKey, genCrc32,

        base64Encode, base64Decode,
        base64EncodePrivate, base64DecodeCore,

        SAMPLE_NUM,
        __SBOX__, __SEED_KEY__, __ROUND_KEY__,
        PRIVATE_B64_ALPHABET, PRIVATE_B64_PADDING,
        BASE64_ALPHABET, BASE64_PADDING,

        encodeTracePoint, buildSliderData,
        sample, unique2DArray,
    };
}
