#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NC dispatcher 自研解密器（纯 Python + Windows BCrypt，不依赖 NC/UClient jar）
按《请求加密解密协议与自研加解密器设计.md》§3/§4 实现。

用法：
  python decrypt_py.py --body  <http_body.bin>   # 输入含 [4B长度+帧] 的完整 HTTP body
  python decrypt_py.py --frame <frame.bin>       # 输入不含 4B 长度前缀的帧
  python decrypt_py.py --self-test               # 用 nc_capture 里真实抓包自测

输出：帧头解析 + AES key + 解密后明文对象流（应 AC ED 00 05 开头）。
"""
import ctypes, sys, zlib, os
from ctypes import wintypes

MAGIC = b"\x72\x71\x89"
SUB = -2719509405472134292  # 0xda425c9ab37feb6c，两补

# ---------- AES-ECB/NoPadding via Windows BCrypt ----------
_alg = None


def _bcrypt_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-128/ECB/NoPadding 解密。data 长度须为 16 的倍数。"""
    global _alg
    bcrypt = ctypes.windll.bcrypt
    BCRYPT_AES = ctypes.c_wchar_p("AES")
    BCRYPT_CHAINING_MODE = ctypes.c_wchar_p("ChainingMode")
    ECB = ctypes.c_wchar_p("ChainingModeECB")

    def ok(code):
        if code != 0:
            raise OSError("BCrypt error 0x%x" % code)

    if _alg is None:
        h = wintypes.HANDLE()
        ok(bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h), BCRYPT_AES, None, 0))
        _alg = h
    h_alg = _alg
    ok(bcrypt.BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE,
                                ctypes.cast(ECB, ctypes.c_void_p),
                                2 * (len("ChainingModeECB") + 1), 0))
    h_key = wintypes.HANDLE()
    ok(bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0,
                                         key, len(key), 0))
    out = ctypes.create_string_buffer(len(data))
    done = wintypes.ULONG(0)
    try:
        ok(bcrypt.BCryptDecrypt(h_key, data, len(data), None, None, 0,
                                out, len(data), ctypes.byref(done), 0))
    finally:
        bcrypt.BCryptDestroyKey(h_key)
    return out.raw[:done.value]


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("ciphertext not block aligned: %d" % len(data))
    return _bcrypt_decrypt(key, data)


# ---------- 纯函数（与文档 §5.3 对齐） ----------

def parse_header(h):
    return {"encrypted": bool(h & 1),
            "compressed": bool((h >> 1) & 1),
            "enc_type": 2 if (h >> 3) & 1 else (1 if (h >> 2) & 1 else 0)}


def gen_aes_key(index: int) -> bytes:
    v = (SUB + index) & 0xFFFFFFFFFFFFFFFF
    # 实测（文档 §3.3 + 黄金 key）：前 8 字节 = (SUB+idx)>>2，后 8 字节 = (SUB+idx)>>4
    hi = (v >> 2) & 0xFFFFFFFFFFFFFFFF
    lo = (v >> 4) & 0xFFFFFFFFFFFFFFFF
    return hi.to_bytes(8, "big") + lo.to_bytes(8, "big")


def unescape(data: bytes) -> bytes:
    """FastAESInputStream 反转义：0x64 0x64→字面 d；孤立 0x64=终止标记（其后丢弃）。"""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == 0x64:
            if i + 1 < n and data[i + 1] == 0x64:
                out.append(0x64); i += 2
            else:
                break  # 终止标记，丢弃其后补零
        else:
            out.append(b); i += 1
    return bytes(out)


def decrypt_frame(nc_frame: bytes) -> dict:
    """入参 = magic+header[+transKey]+密文（不含4B长度）。返回结构化结果。"""
    r = {"ok": False}
    if len(nc_frame) < 5 or nc_frame[:3] != MAGIC:
        r["err"] = "bad magic"; return r
    header = nc_frame[3]
    pf = parse_header(header)
    r["header"] = hex(header)
    r["encrypted"] = pf["encrypted"]
    r["compressed"] = pf["compressed"]
    r["enc_type"] = pf["enc_type"]
    off = 4
    transkey = nc_frame[off] if pf["encrypted"] and pf["enc_type"] == 2 else 0
    if pf["encrypted"] and pf["enc_type"] == 2:
        off += 1
    r["transkey"] = transkey
    r["aes_index"] = transkey & 0x7F if (pf["encrypted"] and pf["enc_type"] == 2) else None
    r["aes_key"] = gen_aes_key(r["aes_index"]) if r["aes_index"] is not None else None
    body = nc_frame[off:]
    try:
        if pf["encrypted"]:
            if pf["enc_type"] == 2:
                dec = aes_ecb_decrypt(r["aes_key"], body)
            else:
                raise ValueError("enc_type=%d 暂未实现" % pf["enc_type"])
            dec = unescape(dec)
        else:
            dec = body
        if pf["compressed"]:
            plain = zlib.decompress(dec)   # RFC1950 zlib 封装
        else:
            plain = dec
    except Exception as e:
        r["err"] = "%s: %s" % (type(e).__name__, e)
        return r
    r["ok"] = True
    r["plain_len"] = len(plain)
    r["plain_head"] = plain[:16]
    r["is_java_serialized"] = plain.startswith(b"\xAC\xED\x00\x05")
    return r


def split_http_body_streams(path):
    """读 srv_*.c2s/s2c，用 Content-Length 切出 dispatcher 帧体，逐条解密。"""
    raw = open(path, "rb").read()
    msgs, i, n = [], 0, len(raw)
    while i < n:
        sep = raw.find(b"\r\n\r\n", i)
        if sep < 0:
            break
        head = raw[i:sep].decode("iso-8859-1", "replace")
        cl = None
        for ln in head.splitlines():
            if ln.lower().startswith("content-length:"):
                cl = int(ln.split(":", 1)[1].strip())
        if cl is None:
            break
        bstart = sep + 4
        msgs.append(raw[bstart: bstart + cl])
        i = bstart + cl
    return msgs


def _load_frame(argv):
    if "--frame" in argv:
        return open(argv[argv.index("--frame") + 1], "rb").read(), "frame"
    if "--body" in argv:
        b = open(argv[argv.index("--body") + 1], "rb").read()
        n = int.from_bytes(b[:4], "big")
        return b[4:4 + n], "body(len=%d)" % n
    return None, None


def _self_test():
    import glob
    capture_dir = os.environ.get("NC_CAPTURE_DIR", os.getcwd())
    cands = glob.glob(os.path.join(capture_dir, "srv_*.c2s"))
    cands += glob.glob(os.path.join(capture_dir, "srv_*.s2c"))
    okn = 0
    for f in cands:
        for mb in split_http_body_streams(f):
            if len(mb) < 8:
                continue
            n = int.from_bytes(mb[:4], "big")
            if 4 + n != len(mb):
                continue
            r = decrypt_frame(mb[4:4 + n])
            tag = "OK " if r.get("ok") else "ERR"
            if r.get("ok"):
                okn += 1
                line = ("[OK ] %s body=%d -> len=%d head=%s java_serialized=%s"
                        % (os.path.basename(f), len(mb), r["plain_len"],
                           r["plain_head"].hex(), r["is_java_serialized"]))
            else:
                line = ("[ERR] %s body=%d -> header=%s err=%s"
                        % (os.path.basename(f), len(mb), r.get("header", "?"), r.get("err", "?")))
            print(line)
    print("\n成功解密帧数:", okn)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _self_test()
    else:
        frame, src = _load_frame(sys.argv)
        if frame is None:
            print(__doc__); sys.exit(1)
        r = decrypt_frame(frame)
        print("来源:", src)
        for k in ("header", "encrypted", "compressed", "enc_type", "transkey",
                  "aes_index", "aes_key"):
            v = r.get(k)
            print("  %-11s %s" % (k, v.hex() if isinstance(v, bytes) else v))
        if r.get("ok"):
            print("  解密结果: OK 明文 %d 字节" % r["plain_len"])
            print("  明文头: %s" % r["plain_head"].hex())
            print("  Java 序列化头(AC ED 00 05)?", r["is_java_serialized"])
        else:
            print("  解密失败:", r.get("err"))
