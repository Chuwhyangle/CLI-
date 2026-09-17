#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
转发器会话的实时监控：盯着 relay 会话目录里新写的 conn_*.txt，
实时打印 C->S / S->C 的 HTTP 请求行与响应状态行。
用法: python liveview.py <relay会话目录>
"""
import os
import sys
import time
import re

DIR = sys.argv[1] if len(sys.argv) > 1 else '.'
print("liveview 监控目录:", os.path.abspath(DIR), "（Ctrl+C 退出）", flush=True)

offsets = {}          # 文件名 -> 已读字节
seen_files = set()

REQ_LINE = re.compile(rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS) \S+ HTTP/\d')
RESP_LINE = re.compile(rb'^HTTP/1\.[01] (\d{3})')


def poll_once():
    global seen_files
    try:
        names = [n for n in os.listdir(DIR) if n.startswith("conn_") and n.endswith(".txt")]
    except Exception:
        return
    for name in sorted(names):
        if name not in seen_files:
            seen_files.add(name)
        path = os.path.join(DIR, name)
        try:
            with open(path, "rb") as f:
                off = offsets.get(name, 0)
                f.seek(off)
                chunk = f.read()
                if not chunk:
                    continue
                offsets[name] = f.tell()
        except Exception:
            continue
        for raw in chunk.split(b"\n"):
            line = raw.rstrip(b"\r")
            if REQ_LINE.match(line):
                print("[%s] C->S %s" % (name[5:8], line.decode("latin1")[:90]), flush=True)
            elif RESP_LINE.match(line):
                print("[%s] S->C %s" % (name[5:8], line.decode("latin1")[:60]), flush=True)


if __name__ == "__main__":
    try:
        while True:
            poll_once()
            time.sleep(0.4)
    except KeyboardInterrupt:
        print("\nliveview 已停止")
