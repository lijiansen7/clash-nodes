#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash 免费节点订阅解析与连通性测试工具
================================================

功能:
1. 自动从 GitHub 仓库 README 中发现 raw 订阅链接
   (也支持直接传入订阅 URL 或本地 YAML 文件)
2. 解析 Clash YAML 配置,提取代理节点 (name/type/server/port)
3. 对每个节点做 TCP 连通性测试 + 延迟测量 (并发)
4. 对 TCP 连通的节点做真实代理协议实测 (trojan / vless / ss,
   真正通过代理协议发 HTTP 请求, 收到目标站 200 才算可用)
5. 输出结果表格;可导出为 Clash YAML 供客户端导入

依赖:  pip install requests pyyaml
可选:  pip install cryptography   (ss 节点协议实测需要)
用法:
  # 1. 从默认仓库自动发现订阅并测试 (含协议实测)
  python clash_node_tester.py --discover --export-alive alive.yaml --export-proxy-ok ok.yaml

  # 2. 直接测试某个订阅链接
  python clash_node_tester.py --url https://raw.githubusercontent.com/xxx/xxx/main/clash.yaml

  # 3. 测试本地文件
  python clash_node_tester.py --file nodes.yaml

  # 4. 只做 TCP 测试, 跳过协议实测
  python clash_node_tester.py --discover --no-proxy-test

  # 5. 自定义代理实测目标站 (默认 example.com:80)
  python clash_node_tester.py --discover --test-host www.google.com --test-port 443

  # 6. 用 mihomo 内核加速测速 (真实协议健康检查, 支持全部协议, 更快)
  #    先下载内核: py get_mihomo.py
  python clash_node_tester.py --discover --engine mihomo --export-proxy-ok ok.yaml

注意: 免费节点不可靠且流量经过第三方,请勿用于敏感操作。
     "协议实测通过" 表示节点能正常代理访问目标站, 但不保证稳定与安全。
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("[ERROR] 缺少依赖 requests, 请先执行: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[ERROR] 缺少依赖 pyyaml, 请先执行: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---- 默认订阅源 (GitHub 仓库 README 中通常指向 raw 链接) ----
BBBBDEFAULT_REPOS = [
    "https://github.com/flik6/Free-Node",
    "https://github.com/jichangx/free-nodes",
    "https://github.com/eclipsebug/Free-servers",
    "https://github.com/Au1rxx/free-vpn-subscriptions",
    "https://github.com/lanzm/MetaFetch",
    "https://github.com/vxiaov/free_proxies",
    "https://github.com/Barabama/FreeNodes",
]

DEFAULT_REPOS = [
    "https://github.com/jichangx/free-nodes",
    "https://github.com/eclipsebug/Free-servers",
    "https://github.com/Au1rxx/free-vpn-subscriptions",
]

# ---- 默认直接订阅/规则链接 (无需发现, 每次必抓) ----
# ACL4SSR 在线规则 Full+AdblockPlus (分流规则, 非节点; 用于生成导出的分流规则)
ACL4SSR_URL = ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/"
               "ACL4SSR_Online_Full_AdblockPlus.ini"
               "?emoji=true&list=false&tfo=false&scv=true&fdn=false&expand=true&sort=false&new_name=true")
DEFAULT_URLS = [
    ACL4SSR_URL,
    "https://raw.githubusercontent.com/shaoyouvip/free/refs/heads/main/all.yaml",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    ),
}

# GitHub 加速代理 (如用户提供的 666.hxlx.eu.org), 用法为在原始 URL 前拼接代理前缀
GH_PROXY = ""

def accelerate(url):
    """给 github.com / raw.githubusercontent.com 链接加上加速代理前缀"""
    if not GH_PROXY:
        return url
    if url.startswith("https://github.com/") or url.startswith("https://raw.githubusercontent.com/"):
        return GH_PROXY.rstrip("/") + "/" + url
    return url

# ---------------- 发现订阅链接 ----------------
def discover_subscription_urls(repo_url, timeout=20):
    """从 GitHub 仓库 README 中发现 raw 订阅链接 (.yaml/.yml/.txt)"""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:/|$)", repo_url)
    if not m:
        return []
    owner, repo = m.group(1), m.group(2)

    # 尝试常见 README 分支
    readme_urls = [
        f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.md",
        f"https://raw.githubusercontent.com/{owner}/{repo}/master/README.md",
        f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.MD",
    ]
    found = set()
    for ru in readme_urls:
        try:
            r = requests.get(accelerate(ru), headers=HEADERS, timeout=timeout)
            if r.status_code != 200:
                continue
        except requests.RequestException:
            continue
        # 匹配 raw.githubusercontent.com 上的 yaml/yml/txt 链接
        for link in re.findall(r"https?://raw\.githubusercontent\.com[^\s)\"'<>\]]+", r.text):
            if re.search(r"\.(ya?ml|txt)(?:[?#]|$)", link, re.IGNORECASE):
                found.add(link)
        # 匹配 github.com/.../raw/ 形式的链接
        for link in re.findall(r"https?://github\.com/[^\s)\"'<>\]]+/raw/[^\s)\"'<>\]]+", r.text):
            if re.search(r"\.(ya?ml|txt)(?:[?#]|$)", link, re.IGNORECASE):
                found.add(link)
    return sorted(found)


# ---------------- 下载订阅 ----------------
def fetch_subscription(url, timeout=30, retries=5):
    """下载订阅内容,返回文本 (文本可能是 Clash YAML 或 base64 节点列表)。
    免费加速器不稳定, 自动多次重试: 先走加速代理, 再尝试原始地址, 交替退避。"""
    targets = [accelerate(url)]
    if accelerate(url) != url:
        targets.append(url)  # 代理失败时回退直连
    last_err = None
    for attempt in range(retries):
        t = targets[attempt % len(targets)]
        try:
            r = requests.get(t, headers=HEADERS, timeout=timeout)
            r.raise_for_status()
            return r.text
        except requests.RequestException as e:
            last_err = e
            time.sleep(1.5 * (attempt + 1))  # 退避: 1.5s, 3s, 4.5s ...
    raise last_err


# ---------------- 解析节点 ----------------
def parse_proxies(text, source_label=""):
    """
    从订阅内容解析代理节点. 优先按 Clash YAML 解析,
    失败时尝试 base64 解码后再用正则提取 ss://, vmess://, trojan:// 节点.
    返回节点列表: [{name,type,server,port,raw}]
    """
    proxies = []

    # 1. 按 Clash YAML 解析
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            for p in data["proxies"]:
                if not isinstance(p, dict):
                    continue
                if "server" in p and "port" in p:
                    proxies.append({
                        "name": str(p.get("name", "unknown")),
                        "type": str(p.get("type", "?")),
                        "server": str(p["server"]),
                        "port": int(p["port"]),
                        "raw": p,
                        "source": source_label,
                    })
            if proxies:
                return proxies
    except yaml.YAMLError:
        pass

    # 2. 尝试 base64 解码 (订阅链接常返回 base64 编码的节点列表)
    decoded = text
    try:
        # 整体 base64 解码
        d = base64.b64decode(text.strip() + "=" * (-len(text.strip()) % 4))
        decoded = d.decode("utf-8", "ignore")
    except Exception:
        pass

    # 3. 用正则从文本/解码文本中提取节点 (server/port 提取能力有限)
    combined = decoded if decoded != text else text
    for line in combined.splitlines():
        line = line.strip()
        if not line:
            continue
        node = parse_node_line(line, source_label)
        if node:
            proxies.append(node)
    return proxies


def _parse_uri_query(body):
    """解析 URI 的 query 参数并做 URL 解码"""
    q = {}
    if "?" in body:
        for kv in body.split("?", 1)[1].split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                q[k] = urllib.parse.unquote(v)
    return q


def parse_node_line(line, source_label):
    """解析单行节点 (ss://, vmess://, trojan://, vless:// ...),
    还原成带完整凭据的 Clash 配置 dict, 供协议实测与导出使用"""
    def wrap(d):
        return {"name": d["name"], "type": d["type"], "server": d["server"],
                "port": d["port"], "raw": d, "source": source_label}

    try:
        if line.startswith("vmess://"):
            # vmess 是 base64 编码的 JSON
            payload = line[len("vmess://"):]
            obj = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", "ignore"))
            d = {
                "name": obj.get("ps") or obj.get("add", "vmess"),
                "type": "vmess",
                "server": str(obj["add"]),
                "port": int(obj["port"]),
                "uuid": obj.get("id", ""),
                "alterId": obj.get("aid", 0),
                "cipher": obj.get("scy", "auto"),
            }
            if obj.get("tls") == "tls":
                d["tls"] = True
            if obj.get("net"):
                d["network"] = obj["net"]
            if obj.get("path"):
                d["ws-path"] = obj["path"]
            if obj.get("host"):
                d["servername"] = obj["host"]
            return wrap(d)

        name = ""
        if "#" in line:
            name = urllib.parse.unquote(line.split("#", 1)[1])

        if line.startswith("ss://"):
            # ss://[base64(method:pass)@]server:port#name  (也支持明文 userinfo)
            body = line[5:].split("#")[0]
            userinfo, _, serverport = body.rpartition("@")
            server, sport = serverport.rsplit(":", 1)
            method = password = ""
            if userinfo:
                try:
                    dec = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
                except Exception:
                    dec = userinfo
                method, _, password = dec.partition(":")
            d = {"name": name or f"ss-{server}:{sport}", "type": "ss",
                 "server": server, "port": int(sport.split("?")[0]),
                 "cipher": method, "password": password}
            return wrap(d)

        if line.startswith(("trojan://", "vless://")):
            scheme = line.split("://", 1)[0]
            body = line[len(scheme) + 3:].split("#")[0]
            cred, _, serverport = body.partition("@")
            server, sport = serverport.split(":", 1)
            port = int(sport.split("?")[0])
            d = {"name": name or f"{scheme}-{server}:{port}", "type": scheme,
                 "server": server, "port": port}
            if scheme == "trojan":
                d["password"] = cred
            else:
                d["uuid"] = cred
            q = _parse_uri_query(body)
            if q.get("sni"):
                d["sni"] = q["sni"]
            if q.get("host"):
                d["servername"] = q["host"]
            if q.get("path"):
                d["ws-path"] = q["path"]
            if q.get("type") in ("tcp", "ws", "grpc", "h2", "http"):
                d["network"] = q["type"]
            if q.get("security") in ("tls", "reality"):
                d["tls"] = True
            if q.get("flow"):
                d["flow"] = q["flow"]
            if q.get("allowInsecure") in ("1", "true"):
                d["skip-cert-verify"] = True
            return wrap(d)
    except Exception:
        return None
    return None


# ---------------- 连通性测试 ----------------
def test_connectivity(server, port, timeout=5):
    """TCP 连通性测试, 返回 (reachable:bool, latency_ms:float|None, err:str|None)"""
    try:
        start = time.time()
        with socket.create_connection((server, port), timeout=timeout):
            latency = (time.time() - start) * 1000
        return True, round(latency, 1), None
    except socket.gaierror as e:
        return False, None, f"DNS:{e}"
    except socket.timeout:
        return False, None, "timeout"
    except OSError as e:
        return False, None, str(e)[:40]


# ---------------- 代理协议实测 (HTTP CONNECT 真实验证) ----------------
# 说明: 对 TCP 连通的节点, 真正按协议握手并发一个 HTTP 请求,
#       收到目标站 (默认 example.com) 的 HTTP 200 才算"代理可用"。
#       vmess / hysteria2 协议复杂 (需专门库), 标记为 untested。

def _tls_context(skip_verify=True):
    ctx = ssl.create_default_context()
    if skip_verify:  # 免费节点证书常自签/不匹配, 测试阶段放宽校验
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接被对端关闭 (EOF)")
        buf += chunk
    return buf


def _read_until(sock, delim, max_bytes=65536):
    buf = b""
    while delim not in buf and len(buf) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


# ---------- trojan ----------
def test_trojan(node, host, port, timeout):
    """trojan 协议: TLS + <sha224(password)hex>\r\nCONNECT host:port\r\n\r\n + HTTP 请求.
    支持 tcp 与 ws (trojan-go) 两种传输。"""
    raw = node["raw"]
    password = raw.get("password") or ""
    sni = raw.get("sni") or raw.get("servername")
    skip = raw.get("skip-cert-verify", True)
    network = raw.get("network", "tcp")
    try:
        sock = socket.create_connection((node["server"], node["port"]), timeout=timeout)
        sock.settimeout(timeout)
        tls = _tls_context(skip).wrap_socket(sock, server_hostname=sni or node["server"])
        tls.settimeout(timeout)
        pass_hex = hashlib.sha224(password.encode()).hexdigest()
        req = (f"{pass_hex}\r\nCONNECT {host}:{port}\r\n\r\n"
               f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n").encode()
        if network in ("", "tcp"):
            tls.sendall(req)
            data = _read_until(tls, b"\r\n\r\n", 8192)
        elif network == "ws":
            wsopts = raw.get("ws-opts") or {}
            path = (raw.get("ws-path") or raw.get("path")
                    or wsopts.get("path") or "/")
            ws_host = node["server"]
            if isinstance(wsopts.get("headers"), dict):
                ws_host = wsopts["headers"].get("Host") or ws_host
            ws_host = sni or ws_host
            tls.sendall(_ws_handshake_bytes(ws_host, path))
            resp = _read_until(tls, b"\r\n\r\n")
            if b"101" not in resp:
                tls.close()
                return "fail", "WS 升级失败"
            tls.sendall(_ws_frame(req, True))   # trojan 请求放入首个 WS 帧
            _b0, data = _ws_read_frame(tls)
        else:
            tls.close()
            return "untested", f"network={network}"
        tls.close()
        if b"200" in data:
            return "ok", "HTTP 200 via trojan"
        status = re.search(rb"HTTP/\S+\s+(\d+)", data)
        return "fail", f"响应 {status.group(1).decode() if status else data[:20]!r}"
    except (ssl.SSLError, socket.timeout, OSError) as e:
        return "fail", str(e)[:40]


# ---------- vless ----------
def _vless_header(uuid_bytes, host, port):
    hdr = b"\x00" + uuid_bytes            # version 0 + UUID
    hdr += b"\x00\x00"                    # addons 长度 (LE)
    hdr += b"\x01"                        # 命令: TCP
    hb = host.encode()
    if len(hb) <= 255:
        hdr += b"\x02" + bytes([len(hb)]) + hb   # 域名
    else:
        hdr += b"\x01" + socket.inet_aton(socket.gethostbyname(host))  # IPv4
    hdr += struct.pack(">H", port)
    return hdr


def _ws_handshake_bytes(host, path):
    key = base64.b64encode(os.urandom(16)).decode()
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()


def _ws_frame(payload, is_binary=True):
    """客户端 WebSocket 帧 (必须掩码)"""
    opcode = 0x02 if is_binary else 0x01
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        header = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", n)
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return header + mask + masked


def _ws_read_frame(sock):
    """读取服务器 WS 帧 (未掩码)"""
    b0, b1 = _read_exact(sock, 2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", _read_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", _read_exact(sock, 8))[0]
    masked = b1 & 0x80
    mask = _read_exact(sock, 4) if masked else b""
    payload = _read_exact(sock, n)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return b0, payload


def test_vless(node, host, port, timeout):
    """vless 协议: (可选 TLS) + VLESS 头 (CONNECT) + HTTP 请求. 支持 tcp / ws 传输"""
    raw = node["raw"]
    try:
        uuid_bytes = uuid.UUID(raw["uuid"]).bytes
    except Exception:
        return "fail", "uuid 无效"
    tls_flag = raw.get("tls", False)
    sni = raw.get("servername") or raw.get("sni")
    skip = raw.get("skip-cert-verify", True)
    network = raw.get("network", "tcp")
    flow = raw.get("flow")
    if flow:
        return "untested", f"flow={flow} 需专用客户端"
    try:
        sock = socket.create_connection((node["server"], node["port"]), timeout=timeout)
        sock.settimeout(timeout)
        if tls_flag:
            sock = _tls_context(skip).wrap_socket(sock, server_hostname=sni or node["server"])
        hdr = _vless_header(uuid_bytes, host, port)
        payload = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
        if network in ("", "tcp"):
            sock.sendall(hdr + payload)
            data = _read_until(sock, b"\r\n\r\n", 8192)
        elif network == "ws":
            wsopts = raw.get("ws-opts") or {}
            path = (raw.get("ws-path") or raw.get("path")
                    or wsopts.get("path") or "/")
            ws_host = node["server"]
            if isinstance(wsopts.get("headers"), dict):
                ws_host = wsopts["headers"].get("Host") or ws_host
            ws_host = sni or ws_host
            sock.sendall(_ws_handshake_bytes(ws_host, path))
            resp = _read_until(sock, b"\r\n\r\n")
            if b"101" not in resp:
                sock.close()
                return "fail", "WS 升级失败"
            sock.sendall(_ws_frame(hdr, True))      # VLESS 头作为首个二进制帧
            sock.sendall(_ws_frame(payload, True))  # HTTP 请求帧
            _b0, data = _ws_read_frame(sock)
        else:
            sock.close()
            return "untested", f"network={network}"
        sock.close()
        if b"200" in data:
            return "ok", "HTTP 200 via vless"
        status = re.search(rb"HTTP/\S+\s+(\d+)", data)
        return "fail", f"响应 {status.group(1).decode() if status else data[:20]!r}"
    except (ssl.SSLError, socket.timeout, OSError) as e:
        return "fail", str(e)[:40]


# ---------- shadowsocks (AEAD) ----------
def _evp_bytes_to_key(password, key_size):
    """shadowsocks 主密钥派生 (迭代 MD5)"""
    m = b""
    prev = b""
    while len(m) < key_size:
        prev = hashlib.md5(prev + password).digest()
        m += prev
    return m[:key_size]


def _hkdf_sha1(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha1).digest()
    t = b""
    out = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha1).digest()
        out += t
        i += 1
    return out[:length]


def _ss_cipher(method):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    key_sizes = {"aes-128-gcm": 16, "aes-192-gcm": 24, "aes-256-gcm": 32,
                 "chacha20-ietf-poly1305": 32, "xchacha20-ietf-poly1305": 32}
    if method in key_sizes:
        cls = AESGCM if method.startswith("aes") else ChaCha20Poly1305
        return cls, key_sizes[method]
    return None, None


def test_ss(node, host, port, timeout):
    """shadowsocks AEAD: salt + 加密的目标地址 + HTTP 请求, 解密响应验证"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  # noqa
    except ImportError:
        return "untested", "需 pip install cryptography"
    raw = node["raw"]
    method = raw.get("cipher") or raw.get("method") or "aes-256-gcm"
    password = raw.get("password") or ""
    if raw.get("plugin"):
        return "untested", "plugin 不支持"
    aead_cls, key_size = _ss_cipher(method)
    if aead_cls is None:
        return "untested", f"cipher={method}"
    try:
        master = _evp_bytes_to_key(password.encode(), key_size)
        salt = os.urandom(key_size)
        subkey = _hkdf_sha1(salt, master, b"ss-subkey", key_size)
        hb = host.encode()
        addr = b"\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port)
        payload = addr + f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
        n0 = (0).to_bytes(12, "big")
        n1 = (1).to_bytes(12, "big")
        len_ct = aead_cls(subkey).encrypt(n0, struct.pack(">H", len(payload)), None)
        data_ct = aead_cls(subkey).encrypt(n1, payload, None)
        with socket.create_connection((node["server"], node["port"]), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(salt + len_ct + data_ct)
            # 读取响应 (分块解密, 服务端 nonce 从 0 独立计数)
            resp_all = b""
            for chunk_i in range(8):
                if len(resp_all) >= 8192:
                    break
                len_ct2 = _read_exact(sock, 18)
                n = struct.unpack(">H", aead_cls(subkey).decrypt(
                    (chunk_i * 2).to_bytes(12, "big"), len_ct2, None))[0]
                data_ct2 = _read_exact(sock, n + 16)
                resp_all += aead_cls(subkey).decrypt(
                    (chunk_i * 2 + 1).to_bytes(12, "big"), data_ct2, None)
                if b"200" in resp_all:
                    break
        if b"200" in resp_all:
            return "ok", "HTTP 200 via ss"
        status = re.search(rb"HTTP/\S+\s+(\d+)", resp_all)
        return "fail", f"响应 {status.group(1).decode() if status else resp_all[:20]!r}"
    except Exception as e:
        return "fail", str(e)[:40]


def test_proxy_protocol(node, host, port, timeout):
    """按节点类型分发协议实测, 返回 (status, detail); status: ok/fail/untested"""
    # 兼容: raw 为字符串的旧数据, 先归一化成 dict
    if not isinstance(node.get("raw"), dict):
        d = node_to_clash_dict(node)
        if not d:
            return "fail", "无法还原节点配置"
        node = dict(node, raw=d)
    t = node["type"]
    if t == "trojan":
        return test_trojan(node, host, port, timeout)
    if t == "vless":
        return test_vless(node, host, port, timeout)
    if t == "ss":
        return test_ss(node, host, port, timeout)
    return "untested", f"type={t} 无内置协议测试"


# ---------------- 导出 ----------------
def node_to_clash_dict(node):
    """把节点转成 Clash proxy dict (raw 为字符串的 ss/trojan/vless 链接也转换)"""
    raw = node.get("raw")
    if isinstance(raw, dict):
        return raw
    line = str(raw)
    name = node["name"]
    try:
        if line.startswith("ss://"):
            rest = line[5:].split("#")[0]
            userinfo, _, serverport = rest.rpartition("@")
            try:
                dec = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
            except Exception:
                dec = userinfo
            method, _, password = dec.partition(":")
            server, sport = serverport.split(":")
            return {"name": name, "type": "ss", "server": server,
                    "port": int(sport), "cipher": method, "password": password}
        if line.startswith("trojan://") or line.startswith("vless://"):
            scheme = line.split("://", 1)[0]
            body = line[len(scheme) + 3:]
            cred, _, serverport = body.partition("@")
            server, sport = serverport.split(":")[:2]
            d = {"name": name, "type": scheme, "server": server,
                 "port": int(sport.split("#")[0])}
            if scheme == "trojan":
                d["password"] = cred
            else:
                d["uuid"] = cred
            # 提取常见参数
            q = re.search(r"\?(.*)", body)
            if q:
                for kv in q.group(1).split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        if k in ("sni", "servername"):
                            d["sni"] = v
                        elif k in ("type", "network"):
                            d["network"] = v
                        elif k in ("security",):
                            d["tls"] = v == "tls"
                        elif k == "path":
                            d[k] = v
            return d
    except Exception:
        return None
    return None


def export_alive_yaml(nodes_alive, out_path, with_rules=True):
    """把可用节点导出为 Clash YAML (raw 为字符串的节点尽力转成 Clash 配置)。
    with_rules=True 时附带基础分流规则: 国内IP直连, 其余走代理组 (默认开启)。"""
    proxies = []
    skipped = 0
    for n in nodes_alive:
        d = node_to_clash_dict(n)
        if d:
            proxies.append(d)
        else:
            skipped += 1
    out = {"proxies": proxies}
    if with_rules and proxies:
        names = [p["name"] for p in proxies]
        out["proxy-groups"] = [
            {"name": "PROXY", "type": "select", "proxies": names},
        ]
        out["rules"] = [
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ]
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(out, f, allow_unicode=True, sort_keys=False)
    print(f"[OK] 导出 {len(proxies)} 个节点到: {out_path}"
          + (f" (跳过无法转换 {skipped} 个)" if skipped else ""))


# ---------------- 进度条 ----------------
class ProgressBar:
    """轻量进度条 (无第三方依赖). 显示 百分比 |条形| 完成数/总数 [已用时间<ETA] 附加信息.
    可与 print 混用: log() 会先清掉进度行再打印消息, 之后由 update() 重绘。"""

    def __init__(self, total, width=40, desc=""):
        self.total = max(int(total), 1)
        self.width = max(width, 10)
        self.desc = desc
        self.start = time.time()
        self.drawn = False

    def _line(self, n, extra=""):
        pct = n / self.total
        filled = int(self.width * pct)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = time.time() - self.start
        eta = elapsed / max(n, 1) * (self.total - n) if n else 0.0
        return ("\r  %s %5.1f%% |%s| %d/%d [%6.1fs<%-6.1fs] %s"
                % (self.desc, pct * 100, bar, n, self.total, elapsed, eta, extra))

    def update(self, n, extra=""):
        sys.stdout.write(self._line(n, extra))
        sys.stdout.flush()
        self.drawn = True

    def log(self, msg):
        """打印一行日志 (不影响进度条布局)"""
        if self.drawn:
            sys.stdout.write("\r" + " " * 120 + "\r")
            sys.stdout.flush()
        print(msg)

    def finish(self, extra=""):
        self.update(self.total, extra)
        sys.stdout.write("\n")
        sys.stdout.flush()
        self.drawn = False


# ---------------- 主流程 ----------------
def main():
    # 加载外部配置
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
        except Exception as e:
            print(f'[WARN] 加载配置文件失败: {e}')
    config_repos = config.get('repos', DEFAULT_REPOS)
    config_urls = config.get('urls', DEFAULT_URLS)
    config_gh_proxy = config.get('gh_proxy', '')
    if not config_gh_proxy:
        config_gh_proxy = 'https://666.hxlx.eu.org'
    
    ap = argparse.ArgumentParser(description="Clash 免费节点订阅解析与连通性测试")
    ap.add_argument("--discover", action="store_true",
                    help="从 DEFAULT_REPOS 的 README 中自动发现订阅链接")
    ap.add_argument("--url", action="append", default=[],
                    help="直接指定订阅 URL (可多次)")
    ap.add_argument("--file", action="append", default=[],
                    help="本地 YAML/节点文件 (可多次)")
    ap.add_argument("--timeout", type=int, default=2,
                    help="单节点测试超时(秒), 默认 2 (mihomo引擎: 健康检查超时, 超过即剔除)")
    ap.add_argument("--workers", type=int, default=50,
                    help="并发测试线程数, 默认 50")
    ap.add_argument("--fetch-timeout", type=int, default=30,
                    help="下载订阅超时(秒), 默认 30")
    ap.add_argument("--export-alive", default="",
                    help="把可用节点导出到该 Clash YAML 路径")
    ap.add_argument("--limit", type=int, default=0,
                    help="仅测试前 N 个节点(0=全部)")
    ap.add_argument("--gh-proxy", default="https://666.hxlx.eu.org",
                    help="GitHub 加速代理前缀(空字符串=直连)")
    ap.add_argument("--proxy-test", dest="proxy_test", action="store_true", default=True,
                    help="对 TCP 连通的节点做真实代理协议实测 (默认开启)")
    ap.add_argument("--no-proxy-test", dest="proxy_test", action="store_false",
                    help="跳过代理协议实测, 仅做 TCP 测试")
    ap.add_argument("--test-host", default="example.com",
                    help="代理实测的目标站 (默认 example.com)")
    ap.add_argument("--test-port", type=int, default=80,
                    help="代理实测的目标端口 (默认 80)")
    ap.add_argument("--export-proxy-ok", default="",
                    help="把协议实测通过的节点导出到该 Clash YAML 路径")
    ap.add_argument("--engine", choices=["python", "mihomo"], default="python",
                    help="测试引擎: python(内置TCP/协议实测) 或 mihomo"
                         "(mihomo内核真实代理协议健康检查, 更快、支持全部协议, 需 mihomo.exe)")
    ap.add_argument("--min-alive", type=int, default=3,
                    help="mihomo引擎: 某订阅可用节点数低于该值时整体剔除该订阅 (默认 3)")
    ap.add_argument("--keep-cn", action="store_true",
                    help="mihomo引擎: 默认剔除 CN 节点, 加此参数则保留")
    args = ap.parse_args()

    global GH_PROXY
    GH_PROXY = args.gh_proxy.strip()
    if GH_PROXY:
        print(f"[INFO] GitHub 加速代理: {GH_PROXY}")

    # ===== mihomo 引擎快速路径: 并发下载 + 缓存 + 内核实测 (推荐) =====
    if args.engine == "mihomo":
        import mihomo_engine as me
        # 让 mihomo 引擎也使用 config.yaml 中的订阅源配置
        me.t.DEFAULT_REPOS = config_repos
        me.t.DEFAULT_URLS = config_urls
        if not os.path.exists("mihomo.exe"):
            print("[ERROR] 未找到 mihomo.exe, 请先运行: py get_mihomo.py")
            return
        print("=" * 60)
        print("[1/3] 下载订阅并解析节点 (并发下载 + 缓存, 走加速代理)")
        print("=" * 60)
        nodes = me.load_nodes_full(cache="_nodes_cache.pkl")
        if args.limit and len(nodes) > args.limit:
            nodes = nodes[:args.limit]
        if not nodes:
            print("[WARN] 没有解析到任何节点, 结束")
            return
        print(f"\n  共 {len(nodes)} 个唯一节点")
        print("=" * 60)
        print(f"[2/3] mihomo 内核实测 (真实代理协议健康检查, 超时 {args.timeout}s)")
        print("=" * 60)
        proxies = []
        for n in nodes:
            d = me.sanitize(n.get("raw"))
            if d:
                d["_source"] = n.get("source", "")
                proxies.append(d)
        proxies = me.make_unique_names(proxies)
        out = args.export_proxy_ok or "mihomo_alive.yaml"
        _results, ok = me.test_with_mihomo(proxies, out_path=out,
                                           check_timeout_ms=max(args.timeout * 1000, 500),
                                           min_alive=args.min_alive,
                                           exclude_cn=not args.keep_cn)
        print("\n[完成] (mihomo 引擎, 结果: {})".format(out))
        return

    sub_urls = list(args.url) + list(DEFAULT_URLS)

    # 1. 发现订阅链接
    if args.discover:
        print("=" * 60)
        print("[1/4] 从 GitHub 仓库发现订阅链接")
        print("=" * 60)
        for repo in config_repos:
            print(f"  扫描 {repo} ...", end=" ", flush=True)
            try:
                urls = discover_subscription_urls(repo, timeout=args.fetch_timeout)
            except Exception as e:
                print(f"失败 ({e})")
                continue
            print(f"发现 {len(urls)} 条")
            for u in urls:
                # 过滤明显非订阅的 (如 LICENSE.txt / README 等);
                # 注意: 不能匹配 \.git, 否则 raw.githubusercontent.com 域名会被误过滤
                if re.search(r"(?:license|readme|changelog)(?:\.|/|$)", u, re.IGNORECASE):
                    continue
                sub_urls.append(u)
        sub_urls = sorted(set(sub_urls))
        print(f"\n  共发现 {len(sub_urls)} 个候选订阅链接:")

    if not sub_urls and not args.file and not args.discover:
        print("[ERROR] 请用 --discover / --url / --file 之一指定来源")
        ap.print_help()
        sys.exit(2)

    # 2. 下载并解析节点
    print("=" * 60)
    print("[2/4] 下载订阅并解析节点")
    print("=" * 60)
    nodes = []
    dl_items = list(args.file) + list(sub_urls)
    if not dl_items:
        print("[WARN] 没有可下载的订阅")
        return
    pb = ProgressBar(len(dl_items), desc="下载订阅")
    done = 0
    for f in args.file:
        done += 1
        try:
            with open(f, "r", encoding="utf-8") as fh:
                text = fh.read()
            n = parse_proxies(text, source_label=f)
            nodes.extend(n)
            pb.log(f"  [OK] 本地文件 {f} → {len(n)} 节点")
        except Exception as e:
            pb.log(f"  [FAIL] 本地文件 {f} → {str(e)[:60]}")
        pb.update(done, extra=f"累计 {len(nodes)} 节点")

    def _grab_url(u):
        """下载并解析单个订阅 (供并发)"""
        if u.lower().endswith(".ini"):
            return "rules", u
        try:
            text = fetch_subscription(u, timeout=args.fetch_timeout)
            return "ok", u, parse_proxies(text, source_label=u)
        except Exception as e:
            return "fail", u, str(e)[:60]

    dl_urls = list(sub_urls)
    done = 0
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(_grab_url, u): u for u in dl_urls}
        for fut in as_completed(futs):
            done += 1
            r = fut.result()
            if r[0] == "rules":
                pb.log(f"  [规则] {r[1]} (规则文件, 非节点)")
            elif r[0] == "ok":
                _, u, n = r
                nodes.extend(n)
                pb.log(f"  [OK] {u} → {len(n)} 节点")
            else:
                _, u, err = r
                pb.log(f"  [FAIL] {u} → {err}")
            pb.update(done, extra=f"累计 {len(nodes)} 节点")
    pb.finish(extra=f"共 {len(nodes)} 节点")

    # 去重 (按 server:port), 后续出现的同节点用其字段补全第一个 (如 txt 版有 path, YAML 版没有)
    seen = {}
    uniq = []
    for n in nodes:
        key = f"{n['server']}:{n['port']}"
        if key in seen:
            # 合并: 用重复项的字段补全缺失字段 (优先 YAML 版已有的)
            first = seen[key]
            if isinstance(n.get("raw"), dict) and isinstance(first.get("raw"), dict):
                for k, v in n["raw"].items():
                    first["raw"].setdefault(k, v)
            continue
        seen[key] = n
        uniq.append(n)
    nodes = uniq
    print(f"\n  共 {len(nodes)} 个唯一节点 (已按 server:port 去重)")
    if args.limit and len(nodes) > args.limit:
        nodes = nodes[:args.limit]
        print(f"  根据 --limit 仅测试前 {len(nodes)} 个")

    if not nodes:
        print("[WARN] 没有解析到任何节点, 结束")
        return

    # 3. 并发测试连通性
    print("=" * 60)
    print(f"[3/4] TCP 连通性测试 (并发={args.workers}, 超时={args.timeout}s)")
    print("=" * 60)
    results = []
    done = 0
    total = len(nodes)
    pb = ProgressBar(total, desc="TCP 连通性测试")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(test_connectivity, n["server"], n["port"], args.timeout): n
            for n in nodes
        }
        for fut in as_completed(futs):
            n = futs[fut]
            done += 1
            try:
                reachable, latency, err = fut.result()
            except Exception as e:
                reachable, latency, err = False, None, str(e)[:40]
            n["reachable"] = reachable
            n["latency"] = latency
            n["err"] = err
            results.append(n)
            pb.update(done, extra=f"可用 {sum(1 for r in results if r['reachable'])}")
    pb.finish(extra=f"可用 {sum(1 for r in results if r['reachable'])}")

    # 3.5 代理协议实测 (只测 TCP 连通的节点)
    alive_tcp = [r for r in results if r["reachable"]]
    if args.proxy_test and alive_tcp:
        print("=" * 60)
        print(f"[3.5] 代理协议实测 (真实 HTTP 请求 -> {args.test_host}:{args.test_port}, "
              f"并发={args.workers})")
        print("=" * 60)
        done = 0
        pb = ProgressBar(len(alive_tcp), desc="代理协议实测")
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {
                ex.submit(test_proxy_protocol, n, args.test_host, args.test_port, args.timeout): n
                for n in alive_tcp
            }
            for fut in as_completed(futs):
                n = futs[fut]
                done += 1
                try:
                    n["proto"], n["proto_detail"] = fut.result()
                except Exception as e:
                    n["proto"], n["proto_detail"] = "fail", str(e)[:40]
                pb.update(done, extra=f"通过 {sum(1 for r in alive_tcp if r.get('proto') == 'ok')}")
        pb.finish(extra=f"通过 {sum(1 for r in alive_tcp if r.get('proto') == 'ok')}")

    # 4. 输出结果
    print("=" * 60)
    print("[4/4] 结果汇总")
    print("=" * 60)
    alive = sorted(alive_tcp, key=lambda r: (r["latency"] if r["latency"] else 9999))
    dead = [r for r in results if not r["reachable"]]

    proxy_ok = [r for r in alive if r.get("proto") == "ok"]
    print(f"\n  总节点: {total}    可用(TCP连通): {len(alive)}    不可达: {len(dead)}")
    if args.proxy_test:
        print(f"  协议实测: 通过(HTTP 200) {len(proxy_ok)}   失败 {sum(1 for r in alive if r.get('proto')=='fail')}"
              f"   未测/不支持 {sum(1 for r in alive if r.get('proto')!='ok' and r.get('proto')!='fail')}")
    print(f"\n  --- 可用节点 (按延迟升序, 前 30) ---")
    if args.proxy_test:
        print(f"  {'#':>3}  {'延迟ms':>7}  {'类型':<8}  {'实测':<7}  {'server':<30}  {'port':<6}  name")
        for i, r in enumerate(alive[:30], 1):
            tag = {"ok": "OK", "fail": "FAIL", "untested": "-"}.get(r.get("proto", ""), "?")
            print(f"  {i:>3}  {r['latency']:>7}  {r['type']:<8}  {tag:<7}  "
                  f"{r['server'][:30]:<30}  {r['port']:<6}  {r['name'][:30]}")
    else:
        print(f"  {'#':>3}  {'延迟ms':>7}  {'类型':<8}  {'server':<30}  {'port':<6}  name")
        for i, r in enumerate(alive[:30], 1):
            print(f"  {i:>3}  {r['latency']:>7}  {r['type']:<8}  "
                  f"{r['server'][:30]:<30}  {r['port']:<6}  {r['name'][:30]}")

    # 协议实测详情 (仅失败/未测的简要原因)
    if args.proxy_test:
        fail_nodes = [r for r in alive if r.get("proto") == "fail"]
        if fail_nodes:
            print(f"\n  --- 协议实测失败原因 (前 15) ---")
            for r in fail_nodes[:15]:
                print(f"  {r['type']:<8} {r['server']}:{r['port']}  {r.get('proto_detail', '')[:50]}")

    # 错误统计
    if dead:
        err_count = {}
        for r in dead:
            tag = (r["err"] or "unknown").split(":")[0]
            err_count[tag] = err_count.get(tag, 0) + 1
        print(f"\n  --- 不可达原因统计 ---")
        for tag, c in sorted(err_count.items(), key=lambda x: -x[1]):
            print(f"  {tag:<10} {c}")

    # 导出
    if args.export_alive:
        export_alive_yaml(alive, args.export_alive)
    if args.export_proxy_ok and proxy_ok:
        export_alive_yaml(proxy_ok, args.export_proxy_ok)

    print("\n[完成]")


if __name__ == "__main__":
    main()
