#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NC 抓包助手 v2.2（GUI）
 - 窗口置顶（可开关）；实时显示 HTTP 核心行；大回包(默认>=10KB，可调)自动标红+疑似表数据
 - 停止后自动解包 -> 生成【业务名_时间戳】目录 + report.md：
     逐 HTTP 消息展示 请求行/状态行 + 完整HTTP头 + body
     * uapws/JSON 明文 body 直接全文；二进制 body 只给 hex
     * dispatcher 密文 -> 附该消息的官方解码 + “自研解密✓”(decrypt_py) 证据
     业务名 = 该会话中第一个“非后台/框架”的 service.method（可读、好找）

命令行：python capture_gui.py decode <x.pcapng> [--raw] [--out <dir>]
"""
import os, sys, re, time, shutil, threading, subprocess
from datetime import datetime

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
WSHARK_DIR = os.environ.get("WIRESHARK_DIR", r"C:\Program Files\Wireshark")
DUMPCAP    = os.path.join(WSHARK_DIR, "dumpcap.exe")
TSHARK     = os.path.join(WSHARK_DIR, "tshark.exe")
UFJDK_JAVA = os.environ.get("NC_JAVA", "java")
CAP_DIR    = os.environ.get("NC_CAPTURE_DIR", BASE_DIR)
SESS_DIR   = os.path.join(CAP_DIR, "sessions")
CODE_HOME  = os.environ.get("NC_CODE_HOME", "")
DECODE_DIR = os.path.join(os.environ.get("TEMP", "/tmp"), "nc_dispatcher_decode")
CAP_PY     = os.path.join(CAP_DIR, "decrypt_py.py")   # 自研纯 Python 解密器
CLIENT_IP  = os.environ.get("NC_CLIENT_IP", "")

# 子进程不弹控制台窗口（Windows；非 Windows 忽略）
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

HOSTS = {
    "配置的目标主机": os.environ.get("NC_TARGET_IP", "127.0.0.1"),
}
MSG_SEP = b"\r\n\r\n"
BODY_CAP = 8000            # 明文 body 报告里展示上限(字符)

# 后台/框架/启动类调用（子串命中即视为噪音，不参与“业务命名”）
BIZ_NOISE = (
    "nc.login.", "IServerEnvironmentService", "IOutDateVersion", "IVoCacheBS",
    "IDBCacheBS", "ITimeService", "RemoteMetaContext", "IMessageQueryService",
    "IMessageLabelColors", "ILabelColorSources", "IClientTaskQry",
    "IIdentitiVerifyService", "SecurityLog", "IUAPQueryBS", "IPropertyService",
    "IOperatelogQueryService", "IOpenNodeRCService", "IBQOlapQueryService",
    "checkMdVersion", "IReftable", "findBillTempletDatas", "queryFuncletModel",
    "getRepLib", "showMessageAlert", "getImHome", "IFuncRegisterQueryService",
    "IFunctionPermissionPubService", "connectTest", "loadCryptTypeKey",
    "checkProductVersion", "getServerTime", "clearCacheByUser",
)


def find_wlan():
    try:
        r = subprocess.run([TSHARK, "-D"], capture_output=True, timeout=20,
                           creationflags=NO_WINDOW)
        out = (r.stdout or b"").decode("utf-8", "replace")
    except Exception:
        return None
    for line in out.splitlines():
        if "(WLAN)" in line:
            return line.split(" ")[1]
    return None


def _target_filter(key):
    ip = HOSTS[key]
    return "host %s and not port 22" % ip


# ================= HTTP 消息解析 =================

def _headers_map(head):
    d = {}
    for ln in head.splitlines()[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            d[k.strip().lower()] = v.strip()
    return d


def _dechunk(raw, start):
    body, i = bytearray(), start
    try:
        while True:
            eol = raw.find(b"\r\n", i)
            if eol < 0:
                return (None, -1)
            size = int(raw[i:eol].split(b";")[0].strip(), 16)
            if size == 0:
                return (bytes(body), eol + 2)
            body += raw[eol + 2: eol + 2 + size]
            i = eol + 2 + size + 2
    except Exception:
        return (None, -1)


def split_http(raw):
    out, i, n = [], 0, len(raw)
    while i < n:
        sep = raw.find(MSG_SEP, i)
        if sep < 0:
            break
        head = raw[i:sep]
        try:
            hs = head.decode("iso-8859-1")
        except Exception:
            break
        hm = _headers_map(hs)
        bstart = sep + 4
        clen = int(hm["content-length"]) if "content-length" in hm else -1
        if clen >= 0:
            avail = n - bstart
            out.append({"headers": hs, "body": raw[bstart: bstart + min(clen, avail)]})
            nxt = bstart + clen
        elif hm.get("transfer-encoding", "").lower() == "chunked":
            body, nxt = _dechunk(raw, bstart)
            if nxt < 0:
                break
            out.append({"headers": hs, "body": body})
        else:
            out.append({"headers": hs, "body": b""})
            nxt = bstart
        if nxt <= i:
            break
        i = nxt
    return out


def _is_dispatcher(msg):
    hm = _headers_map(msg["headers"])
    ct = hm.get("content-type", "")
    first = msg["headers"].splitlines()[0] if msg["headers"] else ""
    return ("ServiceDispatcherServlet" in first
            or "octet-stream" in ct or "x-java-serialized-object" in ct)


def _body_text(msg):
    for enc in ("utf-8", "gbk"):
        try:
            return msg["body"].decode(enc)
        except UnicodeDecodeError:
            continue
    return msg["body"].decode("utf-8", "replace")


def _is_binary(text):
    return any(ord(ch) < 9 or 13 < ord(ch) < 32 for ch in text)


def _body_preview(msg):
    text = _body_text(msg)
    if text and _is_binary(text):
        return False, "二进制 body %d 字节；前64字节 hex：%s" % (len(msg["body"]), msg["body"][:64].hex(" "))
    return True, text


def self_decrypt_body(body):
    """用自研纯 Python 解密器解 dispatcher HTTP body -> (ok, info)。"""
    try:
        sys.path.insert(0, CAP_DIR)
        import decrypt_py as dp
        if len(body) < 4:
            return False, "body 太短"
        n = int.from_bytes(body[:4], "big")
        if 4 + n > len(body):
            return False, "长度前缀越界"
        r = dp.decrypt_frame(body[4:4 + n])
        if not r.get("ok"):
            return False, r.get("err", "解密失败")
        return True, ("明文 %d 字节 head=%s java=%s"
                      % (r["plain_len"], r["plain_head"][:8].hex(), r["is_java_serialized"]))
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)


# 框架/系统类（出现在对象流里但不代表业务，跳过）
_FRAMEWORK_CLASS = {
    "InvocationInfo", "AttachedProps", "OperateLogVO", "RemoteCallInfo",
    "IRemoteCallCombinatorService", "DASInfoStruct", "QueryScheme",
    "LoginRequest", "LoginResponse", "SecurityLogInfo", "SyncPointVersions",
    "CacheGroup", "FuncletModel",
}


def _dispatcher_plain(body):
    """HTTP body(含4B长度前缀) -> 明文对象流 bytes；失败返回 None。"""
    import zlib
    import decrypt_py as dp
    if len(body) < 8:
        return None
    n = int.from_bytes(body[:4], "big")
    if 4 + n > len(body):
        return None
    frame = body[4:4 + n]
    if frame[:3] != b"\x72\x71\x89":
        return None
    pf = dp.parse_header(frame[3])
    off = 4
    if not pf["encrypted"]:
        return None
    if pf["enc_type"] == 2:
        tk = frame[off]; off += 1
        key = dp.gen_aes_key(tk & 0x7F)
    else:
        return None
    try:
        dec = dp.unescape(dp.aes_ecb_decrypt(key, frame[off:]))
    except Exception:
        return None
    if pf["compressed"]:
        try:
            return zlib.decompress(dec)
        except Exception:
            return None
    return dec


_SVC_RE = re.compile(
    rb"nc\.[A-Za-z0-9._]+?\.([A-Za-z][A-Za-z0-9]*(?:Service|Query|Facade|BP|Process|Qry))")


def _biz_name_from_plain(plain):
    """明文对象流里精确扫出第一个业务服务类名，并按 [1字节长度+字符串] 规律取方法名。
    返回 "类名" 或 "类名.方法名"；失败返回 None。"""
    if not plain:
        return None
    for m in _SVC_RE.finditer(plain):
        cls = m.group(1).decode("ascii")
        full = m.group(0).decode("ascii")
        if cls in _FRAMEWORK_CLASS:
            continue
        if any(b in full for b in BIZ_NOISE):
            continue
        # 方法名：服务名结束后的下一字节=长度，其后 length 字节=方法名
        method = None
        end = m.end()
        if end < len(plain):
            ln = plain[end]
            if 0 < ln < 60 and end + 1 + ln <= len(plain):
                cand = plain[end + 1:end + 1 + ln]
                if cand and all(0x20 <= c <= 0x7e for c in cand):
                    try:
                        s2 = cand.decode("ascii")
                        if s2 and s2[0].isalpha():
                            method = s2
                    except Exception:
                        method = None
        return cls + (("." + method) if method else "")
    return None


def _hhmmss(frame_time):
    m = re.search(r"(\d{2}:\d{2}:\d{2})", frame_time)
    return m.group(1) if m else frame_time.strip()[:12]


# ================= 解码（dispatcher，官方类 best-effort） =================

def _sanitize(text):
    return re.sub(r"(userPWD|userPwd|userpwd|password|passwd|pwd)=([^;\s]+)",
                  r"\1=<redacted>", text)


def _java_class(redact):
    return "NcDispatcherDecoderV2" if redact else "NcDispatcherDecoderV3"


def reconstruct_streams(pcap, workdir):
    fields = ["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.payload"]
    cmd = [TSHARK, "-r", pcap, "-Y", "tcp.payload && tcp.port != 22",
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                         creationflags=NO_WINDOW).stdout or ""
    streams = {}
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) < 6:
            continue
        try:
            src, dst, sport, dport = parts[1], parts[2], int(parts[3]), int(parts[4])
        except (ValueError, IndexError):
            continue
        payload = parts[5].strip().replace(":", "")
        if not payload:
            continue
        try:
            blob = bytes.fromhex(payload)
        except ValueError:
            continue
        if (CLIENT_IP and src == CLIENT_IP) or (not CLIENT_IP and src.startswith("192.168.")):
            streams.setdefault(sport, {"c2s": [], "s2c": []})["c2s"].append(blob)
        else:
            streams.setdefault(dport, {"c2s": [], "s2c": []})["s2c"].append(blob)
    written = []
    for port, d in sorted(streams.items()):
        for side in ("c2s", "s2c"):
            raw = b"".join(d[side])
            if raw:
                p = os.path.join(workdir, "srv_%d.%s" % (port, side))
                with open(p, "wb") as fh:
                    fh.write(raw)
                written.append(p)
    return written


def decode_stream(stream_file, redact, timeout=180):
    cls = _java_class(redact)
    cp = DECODE_DIR + ";" + os.path.join(CODE_HOME, "external", "lib", "*")
    cmd = [UFJDK_JAVA, "-cp", cp, cls, stream_file, CODE_HOME]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
    except Exception as e:
        return "DECODE_RUN_ERROR %s" % e
    out = r.stdout or b""
    for enc in ("utf-8", "gbk"):
        try:
            return out.decode(enc)
        except UnicodeDecodeError:
            continue
    return out.decode("utf-8", "replace")


def split_decode_msgs(text):
    chunks, cur = [], []
    for line in text.splitlines():
        if line.startswith("MESSAGE ") and cur:
            chunks.append("\n".join(cur))
            cur = []
        cur.append(line)
    if cur:
        chunks.append("\n".join(cur))
    return chunks


def _render_call(chunk):
    """抽 service.method（不负责摘要文案）。取不到返回 (None, exc)。"""
    svc = meth = exc = None
    for line in chunk.splitlines():
        s = line.strip()
        if "getServiceName=" in s and svc is None:
            svc = s.split("=", 1)[1].strip()
        elif "getMethodName=" in s and meth is None:
            meth = s.split("=", 1)[1].strip()
        elif "appexception=" in s and exc is None and "null" not in s:
            exc = s.split("=", 1)[1].strip()
    if svc and meth:
        return "%s.%s" % (svc, meth), exc
    return None, exc


# ================= 业务名识别 / 文件安全命名 =================

def _pretty_call(call):
    """service.method -> 只留类名.method（去掉包前缀），如 ICountryQryService.queryAll。"""
    svc, _, meth = call.rpartition(".")
    if not svc or not meth:
        return call
    return svc.split(".")[-1] + "." + meth


def _biz_name(chunks):
    """按顺序取第一个“非后台/框架”的 service.method（取回时压缩成 类名.方法）。"""
    fallback = None
    for c in chunks:
        call, _ = _render_call(c)
        if not call:
            continue
        is_noise = any(b in call for b in BIZ_NOISE)
        is_agg = "doRemoteCall" in call
        if is_noise:
            continue
        if fallback is None and not is_agg:
            fallback = _pretty_call(call)
        if not is_agg and not is_noise:
            return _pretty_call(call)
    return fallback


def safe_name(name):
    name = re.sub(r'[\\/:*?"<>|\s]+', "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name[:70] or "session"


# ================= 报告生成 =================

def decode_pcap_to_report(pcap, out_dir=None, redact=True):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = SESS_DIR if out_dir is None else out_dir
    tmp = os.path.join(base, "_tmp_" + ts)
    os.makedirs(os.path.join(tmp, "work"), exist_ok=True)
    shutil.copy2(pcap, os.path.join(tmp, os.path.basename(pcap)))
    streams = reconstruct_streams(pcap, os.path.join(tmp, "work"))

    # 先解全部 c2s，识别业务名
    groups = {}
    for sp in streams:
        m = re.search(r"srv_(\d+)\.(c2s|s2c)$", os.path.basename(sp))
        if m:
            groups.setdefault(m.group(1), {})[m.group(2)] = sp
    biz = None
    calls_in_order = []
    dec_cache = {}   # dec_cache[port] = {"c2s": chunks, "s2c": chunks}，两个方向各自独立
    for port in sorted(groups, key=int):
        sp = groups[port].get("c2s")
        if not sp:
            continue
        dec = _sanitize(decode_stream(sp, redact))
        chunks = split_decode_msgs(dec)
        dec_cache.setdefault(port, {})["c2s"] = chunks
        with open(os.path.join(tmp, "work", "dec_%s_c2s.txt" % port), "w", encoding="utf-8") as fh:
            fh.write(dec)
        if biz is None:
            n = _biz_name(chunks)
            if n:
                biz = n
                calls_in_order.append(n)
    dirname = "%s_%s" % (safe_name(biz or "no_biz"), ts)
    sess = os.path.join(base, dirname)
    try:
        os.rename(tmp, sess)
    except Exception:
        shutil.move(tmp, sess)
    work = os.path.join(sess, "work")
    # rename 后，groups 里存的还是 _tmp_ 旧路径，改指到新 work
    for _p in groups:
        for _s in list(groups[_p]):
            if groups[_p][_s]:
                groups[_p][_s] = os.path.join(work, os.path.basename(groups[_p][_s]))

    # 再解 s2c，并写 dec 文件（供人工查阅）；c2s 的 chunks 已在上面存进 dec_cache
    for port in sorted(groups, key=int):
        sp_s2c = groups[port].get("s2c")
        if sp_s2c:
            dec = _sanitize(decode_stream(sp_s2c, redact))
            dec_cache.setdefault(port, {})["s2c"] = split_decode_msgs(dec)
            with open(os.path.join(work, "dec_%s_s2c.txt" % port), "w", encoding="utf-8") as fh:
                fh.write(dec)

    L = []
    L.append("# 抓包解码报告  ·  %s" % ts)
    L.append("")
    L.append("- 源 pcap：`%s`" % os.path.basename(pcap))
    L.append("- **业务名**：`%s`" % (biz or "未识别（可能无业务调用）"))
    L.append("- 脱敏：%s" % ("是（账号打码）" if redact else "否（真实账号）"))
    L.append("")

    if not groups:
        L.append("**未抓到 HTTP 业务流。**")
        L.append("原始 pcap 保留在会话目录，可用 decrypt_py.py 单独处理。")

    for port in sorted(groups, key=int):
        g = groups[port]
        L.append("## 连接 %s" % port)
        L.append("")
        for side, title in (("c2s", "客户端 → 服务器（请求）"), ("s2c", "服务器 → 客户端（响应）")):
            sp = g.get(side)
            if not sp:
                continue
            chunks = dec_cache.get(port, {}).get(side, [])
            L.append("### %s" % title)
            L.append("")
            msgs = split_http(open(sp, "rb").read())
            didx = 0
            for k, msg in enumerate(msgs, 1):
                hm = _headers_map(msg["headers"])
                head_lines = msg["headers"].splitlines()
                L.append("#### 消息 %d" % k)
                L.append("")
                L.append("```")
                L.append("\n".join(head_lines[:40]))
                L.append("```")
                L.append("")
                disp = _is_dispatcher(msg)
                if disp:
                    didx += 1
                    L.append("> 类型：**dispatcher（加密）**  ·  第 %d 条  ·  body %d 字节"
                             % (didx, len(msg["body"])))
                    ok, info = self_decrypt_body(msg["body"])
                    L.append("> **自研解密**：%s%s" % ("OK  " if ok else "FAIL ", info))
                    L.append("")
                    if didx - 1 < len(chunks):
                        chunk = chunks[didx - 1]
                        call, exc = _render_call(chunk)
                        if call:
                            L.append("**官方解码调用**：`%s`  %s"
                                     % (call, ("⚠️ " + exc) if exc else ""))
                        else:
                            L.append("> 官方解码：未能还原对象字段（离线受限/RMI stub），"
                                     "明文对象流已由自研解密给出，可查 dec_%s_%s.txt。"
                                     % (port, side))
                        L.append("")
                        L.append("```")
                        L.append(chunk.rstrip())
                        L.append("```")
                    L.append("")
                else:
                    ct = hm.get("content-type", "")
                    pretty = "text" if ("json" in ct or "text" in ct or "xml" in ct
                                        or "urlencoded" in ct) else "binary/other"
                    is_text, text = _body_preview(msg)
                    L.append("> 类型：**明文 %s**  ·  body %d 字节"
                             % (pretty, len(msg["body"])))
                    L.append("")
                    if is_text:
                        if text.strip():
                            shown = text[:BODY_CAP]
                            L.append("```")
                            L.append(shown.rstrip())
                            if len(text) > BODY_CAP:
                                L.append("...（body 共 %d 字符，截断）" % len(text))
                            L.append("```")
                    else:
                        L.append("> " + text)
                    L.append("")
        L.append("")

    report = os.path.join(sess, "report.md")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    return report, sess


# ================= GUI =================

class CaptureApp:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk, scrolledtext
        self.root = root
        root.title("NC 抓包助手 v2.2")
        root.geometry("920x560")
        root.attributes("-topmost", True)
        self.dump = None
        self.ts = None
        self.pcap = None
        self.livefile = None
        self.live_offset = 0
        self.pend_dir = None
        self.sess_dir = None

        top = ttk.Frame(root, padding=6); top.pack(fill="x")
        ttk.Label(top, text="抓包目标:").pack(side="left")
        self.target = ttk.Combobox(top, values=list(HOSTS.keys()), state="readonly", width=24)
        self.target.set(next(iter(HOSTS)))
        self.target.pack(side="left", padx=4)
        self.raw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="真实账号(不打码)", variable=self.raw_var).pack(side="left", padx=4)
        self.top_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="窗口置顶", variable=self.top_var,
                        command=self._toggle_top).pack(side="left", padx=4)
        ttk.Label(top, text="标红≥(KB):").pack(side="left", padx=(8, 2))
        self.thr_var = tk.StringVar(value="10")
        ttk.Spinbox(top, from_=1, to=1048576, width=6, textvariable=self.thr_var).pack(side="left")

        btn = ttk.Frame(root, padding=(6, 0, 6, 4)); btn.pack(fill="x")
        self.b_start = ttk.Button(btn, text="▶ 开始抓包", command=self.start)
        self.b_start.pack(side="left")
        self.b_stop = ttk.Button(btn, text="■ 停止并解包", command=self.stop_and_decode, state="disabled")
        self.b_stop.pack(side="left", padx=6)
        self.b_open = ttk.Button(btn, text="打开结果文件夹", command=self.open_sess, state="disabled")
        self.b_open.pack(side="left", padx=6)
        self.b_clr = ttk.Button(btn, text="清空", command=self.clear_log)
        self.b_clr.pack(side="left")

        mid = ttk.Frame(root, padding=6); mid.pack(fill="both", expand=True)
        self.log = scrolledtext.ScrolledText(mid, wrap="none", font=("Consolas", 9), state="disabled")
        self.log.pack(fill="both", expand=True)
        self.log.tag_configure("big", foreground="#b00000", background="#ffe4e4")
        self.log.tag_configure("ok", foreground="#008000")
        self.log.tag_configure("info", foreground="#444444")
        self.status = ttk.Label(root, relief="sunken", anchor="w", padding=4,
                                text="就绪 | WLAN: %s" % (find_wlan() or "未找到网卡"))
        self.status.pack(fill="x", side="bottom")
        self.append("[提示] 选目标 → 开始 → 去客户端操作 → 停止并解包。≥阈值回包自动标红。"
                    "解包后目录自动按“业务名_时间”命名。", "info")
        self.root.after(600, self._poll_live)

    def _toggle_top(self):
        self.root.attributes("-topmost", bool(self.top_var.get()))

    def append(self, msg, tag=None):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n", tag or ())
        self.log.see("end")
        self.log.config(state="disabled")

    def clear_log(self):
        self.log.config(state="normal"); self.log.delete("1.0", "end"); self.log.config(state="disabled")

    def start(self):
        import tkinter.messagebox as mb
        wlan = find_wlan()
        if not wlan:
            mb.showerror("错误", "找不到 WLAN 网卡"); return
        if self.dump and self.dump.poll() is None:
            mb.showinfo("提示", "已在抓包中"); return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.pend_dir = os.path.join(SESS_DIR, "_pending_" + ts)
        os.makedirs(self.pend_dir, exist_ok=True)
        self.pcap = os.path.join(self.pend_dir, "session.pcapng")
        flt = _target_filter(self.target.get())
        try:
            self.dump = subprocess.Popen([DUMPCAP, "-i", wlan, "-f", flt,
                                          "-a", "duration:1800", "-w", self.pcap],
                                         creationflags=NO_WINDOW)
        except Exception as e:
            mb.showerror("启动失败", str(e)); return
        self.livefile = os.path.join(self.pend_dir, "live.txt")
        lf = open(self.livefile, "wb")
        try:
            self.ts = subprocess.Popen(
                [TSHARK, "-i", wlan, "-f", flt, "-l",
                 "-Y", "http.request or http.response",
                 "-T", "fields", "-E", "separator=|",
                 "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
                 "-e", "http.request.method", "-e", "http.request.uri",
                 "-e", "http.response.code", "-e", "http.content_length",
                 "-e", "http.content_type", "-e", "http.file_data"],
                stdout=lf, stderr=subprocess.DEVNULL,
                creationflags=NO_WINDOW)
        except Exception:
            lf.close(); self.ts = None
        self.live_offset = 0
        self.b_start.config(state="disabled"); self.b_stop.config(state="normal")
        self.append("[开始] 目标=%s  临时目录=%s" % (self.target.get(), self.pend_dir), "ok")
        self.status.config(text="抓包中… WLAN")

    def _poll_live(self):
        if self.livefile and os.path.exists(self.livefile):
            try:
                with open(self.livefile, "rb") as fh:
                    fh.seek(self.live_offset)
                    data = fh.read()
                    self.live_offset += len(data)
                for raw in data.decode("utf-8", "replace").splitlines():
                    p = raw.split("|")
                    if len(p) < 9:
                        continue
                    ts = _hhmmss(p[0])
                    method, uri = p[3].strip(), p[4].strip()
                    code, clen, ctype = p[5].strip(), p[6].strip(), p[7].strip()
                    fdata = p[8].strip()
                    if not (method or code):
                        continue
                    size = int(clen) if clen.isdigit() else 0
                    try:
                        thr = int(self.thr_var.get()) * 1024
                    except Exception:
                        thr = 10 * 1024
                    if method:
                        # 请求：尝试实时自研解密，扫出业务服务名
                        name = None
                        if fdata:
                            try:
                                body = bytes.fromhex(fdata.replace(":", ""))
                                name = _biz_name_from_plain(_dispatcher_plain(body))
                            except Exception:
                                name = None
                        if name:
                            line = "[%s] ▶ %s  (%s)" % (ts, name,
                                                         ("%dB" % size) if size else "")
                        elif "uapws" in uri or "rest" in uri:
                            line = "[%s] ▶ %s %s  (%s)" % (ts, method, uri,
                                                           ("%dB" % size) if size else "")
                        else:
                            line = "[%s] ▶ 加密调用 %s  (%s)" % (ts, uri,
                                                                 ("%dB" % size) if size else "")
                        self.append(line, None)
                    else:
                        # 响应：缩进显示，大包标红
                        line = "[%s]      ◀ HTTP %s  %s  %s" % (ts, code,
                                                                ("%dB" % size) if size else "",
                                                                ctype)
                        big = (thr > 0) and (size >= thr)
                        if big:
                            line += "  ← 大回包/表数据"
                        self.append(line, "big" if big else None)
            except Exception:
                pass
        self.root.after(600, self._poll_live)

    def stop_and_decode(self):
        import tkinter.messagebox as mb
        if self.dump is None:
            return
        self.b_stop.config(state="disabled")
        self.status.config(text="正在停止抓包…")
        for proc in (self.ts, self.dump):
            if proc and proc.poll() is None:
                try: proc.terminate()
                except Exception: pass
        time.sleep(1.0)
        for proc in (self.ts, self.dump):
            if proc and proc.poll() is None:
                try: proc.kill()
                except Exception: pass
        self.dump = self.ts = None
        self.append("[停止] 已停，开始解包…", "ok")
        threading.Thread(target=self._do_decode, daemon=True).start()

    def _do_decode(self):
        try:
            report, sess = decode_pcap_to_report(self.pcap, redact=not self.raw_var.get())
            # 把 live.txt 并入最终会话目录，并清掉临时目录
            if self.pend_dir and os.path.isdir(self.pend_dir) and self.livefile \
                    and os.path.exists(self.livefile):
                try:
                    shutil.move(self.livefile, os.path.join(sess, "live.txt"))
                except Exception:
                    pass
            if self.pend_dir and os.path.isdir(self.pend_dir):
                try:
                    shutil.rmtree(self.pend_dir, ignore_errors=True)
                except Exception:
                    pass
            self.root.after(0, lambda: self._decode_done(report, sess))
        except Exception as e:
            import traceback
            self.root.after(0, lambda: self._decode_done(None, None,
                                                         str(e) + "\n" + traceback.format_exc()))

    def _decode_done(self, report, sess, err=None):
        import tkinter.messagebox as mb
        self.b_start.config(state="normal"); self.b_stop.config(state="disabled")
        if err:
            self.status.config(text="解包出错")
            mb.showerror("解包出错", err); return
        self.sess_dir = sess
        self.b_open.config(state="normal")
        self.status.config(text="完成 | " + report)
        self.append("[完成] 会话目录 = %s" % os.path.dirname(report), "ok")
        self.append("[完成] 报告      = %s" % report, "ok")
        mb.showinfo("完成", "解包完成，已按业务名命名：\n" + os.path.dirname(report))

    def open_sess(self):
        if self.sess_dir and os.path.isdir(self.sess_dir):
            os.startfile(self.sess_dir)  # type: ignore


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "decode":
        pcap = sys.argv[2]
        redact = "--raw" not in sys.argv
        out = None
        if "--out" in sys.argv:
            out = sys.argv[sys.argv.index("--out") + 1]
        r, s = decode_pcap_to_report(pcap, out_dir=out, redact=redact)
        print("REPORT:", r)
        print("SESSION:", s)
        sys.exit(0)
    import tkinter as tk
    root = tk.Tk()
    CaptureApp(root)
    root.mainloop()
