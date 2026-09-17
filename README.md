# NC Capture Tools

用于分析经过 HTTP 传输的 NC/UAP 客户端流量，包含：

- TCP payload 提取与双向流重组
- HTTP 请求和响应拆分
- NC Dispatcher 帧扫描
- Dynamic AES 解密、zlib 解压和 Java 序列化识别
- 可选的 NC `NetObjectInputStream` Java 对象解码器
- Windows 抓包 GUI 和本地 HTTP 测试服务器

仓库只包含通用工具代码，不包含任何抓包文件、会话日志、账号、Cookie、内网地址或业务报告。

## 环境变量

Windows PowerShell 示例：

```powershell
$env:NC_TARGET_IP = "目标服务器 IP"
$env:NC_CLIENT_IP = "客户端 IP"
$env:WIRESHARK_DIR = "C:\Program Files\Wireshark"
$env:NC_JAVA = "java.exe"
$env:NC_CODE_HOME = "本机 NC 客户端 NCCACHE\CODE 目录"
```

其中 `NC_TARGET_IP`、`NC_CLIENT_IP` 和 `NC_CODE_HOME` 必须替换为当前授权测试环境的值，不要把它们写入源代码。

## 使用方式

提取 TCP 双向流：

```powershell
python pcap2streams.py sample.pcapng work
```

扫描 Dispatcher 报文：

```powershell
python pcap_disp_scan.py sample.pcapng
```

生成 HTTP 分析结果：

```powershell
python pcap_http_analyze.py sample.pcap
```

使用 GUI 解码已有抓包：

```powershell
python capture_gui.py decode sample.pcapng --out sessions
```

纯 Python 解密器支持单帧测试：

```powershell
python decrypt_py.py --frame frame.bin
python decrypt_py.py --self-test
```

Java 对象解码器需要本机 NC 客户端类库，并使用 `NC_CODE_HOME` 指向其 `NCCACHE\CODE` 目录。不要对来源不可信的字节流执行 Java 反序列化。

## 安全要求

- 只分析自己有权访问的网络流量。
- 不要提交 `.pcap`、`.pcapng`、`.c2s`、`.s2c`、Cookie、密码或业务数据。
- 推送前检查 `git status` 和 `git diff --cached`。
- 如果抓包中出现账号、令牌或密码，应立即按已暴露凭据处理并更换。
