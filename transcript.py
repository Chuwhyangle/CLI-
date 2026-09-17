#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 relay 会话目录(conn_*.c2s / .s2c)逐条转成"详细可读"HTTP 转录：
  请求: 方法 + 完整路径(含查询参数) + Content-Type/Length
  响应: 状态 + Content-Type + 长度 + 明文内容(JSON/文本看全文, 密文/二进制给长度+前16字节)
用法: python transcript.py <会话目录> [> out.txt]
"""
import os
import re
import sys
import glob


def iter_http(raw):
    i, n = 0, len(raw)
    while i < n:
        j = raw.find(b"\r\n\r\n", i)
        if j < 0:
            break
        head = raw[i:j]
        rest = j + 4
        body = b""
        m = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
        if m:
            cl = int(m.group(1))
            body = raw[rest:rest + cl]
            rest += cl
        yield head, body
        i = rest


def hdr(head, name):
    m = re.search((name + r":\s*(.+)").encode(), head, re.I)
    return m.group(1).decode("latin1").strip() if m else ""


def show_body(head, body):
    ct = hdr(head, "Content-Type").lower()
    if "json" in ct or "text" in ct or ct.startswith("application/xml"):
        txt = body.decode("utf-8", "replace")
        return "BODY(%dB) %s" % (len(body), txt[:400])
    # 二进制/NC序列化/octet：给长度 + 帧头
    first = body[:16].hex()
    return "BODY(%dB hex16=%s) [密文/二进制, 需解码看业务]" % (len(body), first)


def fmt_req(head, body):
    first = head.split(b"\r\n", 1)[0].decode("latin1")
    return ("  C->S %s\n"
            "        Content-Type: %s | Content-Length: %s\n"
            "        %s") % (first, hdr(head, "Content-Type"), hdr(head, "Content-Length"),
                             show_body(head, body))


def fmt_resp(head, body):
    first = head.split(b"\r\n", 1)[0].decode("latin1")
    return ("  S->C %s\n"
            "        Content-Type: %s | Content-Length: %s\n"
            "        %s") % (first, hdr(head, "Content-Type"), hdr(head, "Content-Length"),
                             show_body(head, body))


def main():
    d = sys.argv[1]
    c2s = sorted(glob.glob(os.path.join(d, "conn_*.c2s")))
    for cf in c2s:
        cn = os.path.basename(cf)[5:8]
        sf = cf[:-3] + "s2c"
        with open(cf, "rb") as f:
            reqs = list(iter_http(f.read()))
        resps = []
        if os.path.exists(sf):
            with open(sf, "rb") as f:
                resps = list(iter_http(f.read()))
        print("========== 连接 #%s : 请求 %d / 响应 %d ==========" % (cn, len(reqs), len(resps)))
        for i in range(max(len(reqs), len(resps))):
            if i < len(reqs):
                print(fmt_req(*reqs[i]))
            if i < len(resps):
                print(fmt_resp(*resps[i]))
        print()


if __name__ == "__main__":
    main()
