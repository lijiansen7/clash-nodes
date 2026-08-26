# -*- coding: utf-8 -*-
"""mihomo 内核加速连通性测试
用法:
  py mihomo_engine.py --quick            # 用 alive_nodes.yaml 验证管道
  py mihomo_engine.py --full             # 全量: 发现+下载全部订阅后测所有节点
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, ".")
import requests
import yaml

import clash_node_tester as t

if not t.GH_PROXY:
    t.GH_PROXY = os.environ.get("GH_PROXY", "https://666.hxlx.eu.org")
BLOCKED_FILE = "blocked_subs.txt"
ACC = t.GH_PROXY
API = "http://127.0.0.1:19090"
WORKDIR = "_mihomo"


def sanitize(d):
    """清理节点配置, 返回 mihomo 可用的 Clash dict 或 None"""
    if not isinstance(d, dict) or not d.get("server") or not d.get("port"):
        return None
    try:
        port = int(d.get("port"))
        if not 1 <= port <= 65535:
            return None
    except (TypeError, ValueError):
        return None
    typ = d.get("type")
    if typ not in ("ss", "vmess", "vless", "trojan", "hysteria2", "hysteria"):
        return None
    d = dict(d)
    d["port"] = port
    if typ == "ss" and (not d.get("cipher") or not d.get("password")):
        return None
    if typ == "trojan" and not d.get("password"):
        return None
    if typ in ("vless", "vmess"):
        if not d.get("uuid"):
            return None
        try:
            uuid.UUID(str(d["uuid"]))
        except Exception:
            return None
    if typ == "vless":
        # 部分新订阅带量子安全加密参数 (mlkem768x25519plus 等), 当前 mihomo 不支持
        if d.get("encryption") and d["encryption"] != "none":
            d.pop("encryption", None)
    if typ in ("hysteria2", "hysteria") and not d.get("password"):
        return None
    sni = d.get("sni") or d.get("servername")
    if sni and ("://" in str(sni) or " " in str(sni)):
        d.pop("sni", None)
        d.pop("servername", None)
    # 清理非法 network
    net = d.get("network")
    if net and net not in ("tcp", "ws", "grpc", "h2", "http"):
        d["network"] = "tcp"
    if typ == "vmess" and d.get("network") in ("raw", None, ""):
        d.pop("network", None)
    # reality: 校验 short-id / public-key, 非法则整个节点丢弃
    ro = d.get("reality-opts")
    if ro is not None:
        pub = ro.get("public-key") or ""
        sid = str(ro.get("short-id") or "")
        if len(pub) < 30 or len(sid) > 32 or (len(sid) % 2 != 0) or not re.fullmatch(r"[0-9a-fA-F]*", sid):
            return None
    # flow 只在 reality 下保留
    if d.get("flow") and not d.get("reality-opts"):
        d.pop("flow", None)
    # client-fingerprint 白名单
    fp = d.get("client-fingerprint")
    if fp and fp not in ("chrome", "firefox", "safari", "ios", "android",
                         "edge", "360", "qq", "random", "none"):
        d.pop("client-fingerprint", None)
    return d


def load_nodes_full(cache="_nodes_cache.pkl"):
    """全量: 发现 + 下载 + 解析 + 去重合并; 结果缓存到 pkl, 重复运行秒加载"""
    import pickle
    if os.path.exists(cache):
        try:
            with open(cache, "rb") as f:
                nodes = pickle.load(f)
            print(f"[cache] 从 {cache} 加载 {len(nodes)} 个节点")
            return nodes
        except Exception:
            pass
    sub_urls = list(t.DEFAULT_URLS)
    for repo in t.DEFAULT_REPOS:
        try:
            urls = t.discover_subscription_urls(repo, timeout=30)
        except Exception:
            continue
        for u in urls:
            if re.search(r"(?:license|readme|changelog)(?:\.|/|$)", u, re.IGNORECASE):
                continue
            sub_urls.append(u)
    sub_urls = sorted(set(sub_urls))
    # 读取屏蔽列表, 跳过已被屏蔽的订阅源 (可用节点过少的来源会自动加入)
    blocked = set()
    if os.path.exists(BLOCKED_FILE):
        try:
            with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
                blocked = {line.strip() for line in f if line.strip()}
        except Exception:
            blocked = set()
    if blocked:
        before = len(sub_urls)
        sub_urls = [u for u in sub_urls if u not in blocked]
        print(f"[filter] 屏蔽列表 {len(blocked)} 条, 跳过 {before - len(sub_urls)} 个订阅源, 剩余 {len(sub_urls)}", flush=True)
    nodes = []

    def grab(u):
        if u.lower().endswith(".ini"):
            return []
        try:
            text = t.fetch_subscription(u, timeout=60)
            return t.parse_proxies(text, source_label=u)
        except Exception:
            return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    dl = [u for u in sub_urls if not u.lower().endswith(".ini")]
    done = 0
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(grab, u): u for u in dl}
        for f in as_completed(futs):
            u = futs[f]
            done += 1
            try:
                r = f.result()
            except Exception:
                r = None
            if r is None:
                print(f"  [FAIL] {u.split('/')[-1][:40]}", flush=True)
            else:
                nodes.extend(r)
                print(f"  [{done}/{len(dl)}] {u.split('/')[-1][:40]} 累计 {len(nodes)}", flush=True)
    seen, uniq = {}, []
    for n in nodes:
        key = f"{n['server']}:{n['port']}"
        if key in seen:
            first = seen[key]
            if isinstance(n.get("raw"), dict) and isinstance(first.get("raw"), dict):
                for k, v in n["raw"].items():
                    first["raw"].setdefault(k, v)
            continue
        seen[key] = n
        uniq.append(n)
    with open(cache, "wb") as f:
        pickle.dump(uniq, f)
    print(f"[cache] 已保存 {len(uniq)} 个节点到 {cache}")
    return uniq


class QuotedSafeDumper(yaml.SafeDumper):
    """PyYAML 与 go-yaml 解析规则不同: 像 017184 这类字符串 PyYAML 会不加引号输出,
    但 mihomo(go-yaml, YAML 1.1)会按八进制解析成数字。强制给这类字符串加引号。"""


def _quote_str(dumper, data):
    if re.fullmatch(r"[-+]?(0[xob]?[0-9a-fA-F_]+|\d+\.?\d*|\.\d+)"
                    r"|true|false|yes|no|on|off|null|~|True|False|NULL|Yes|No|On|Off|~", data):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


QuotedSafeDumper.add_representer(str, _quote_str)


def build_config(proxies, check_timeout_ms=2000):
    """内部测试用配置: select 组 (不自动健康检查, 由并发 /delay API 驱动测速)"""
    os.makedirs(WORKDIR, exist_ok=True)
    cfg = {
        "mixed-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "external-controller": API.split("//")[1],
        "proxies": proxies,
        "proxy-groups": [
            {"name": "ALL", "type": "select",
             "proxies": [p["name"] for p in proxies]},
        ],
        "rules": ["MATCH,DIRECT"],
    }
    with open(os.path.join(WORKDIR, "config.yaml"), "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False, Dumper=QuotedSafeDumper)


def parallel_delay_test(proxies, url="http://www.gstatic.com/generate_204",
                        timeout_ms=2000, concurrency=150):
    """并发调用 mihomo /delay API 实测每个节点 (真实协议), 返回 {name: delay_ms}。
    相比内核自动健康检查(~24并发), 这里可把并发拉到 150, 大幅提速。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    delays = {}
    req_timeout = timeout_ms / 1000 + 3

    def test(p):
        try:
            r = requests.get(API + "/proxies/" + urllib.parse.quote(p["name"]) + "/delay",
                             params={"url": url, "timeout": timeout_ms},
                             timeout=req_timeout)
            d = r.json().get("delay")
            return p["name"], (d if d and d > 0 else None)
        except Exception:
            return p["name"], None

    done = 0
    total = len(proxies)
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {ex.submit(test, p): p for p in proxies}
        for fut in as_completed(futs):
            name, delay = fut.result()
            delays[name] = delay
            done += 1
            if done % 300 == 0 or done == total:
                alive = sum(1 for v in delays.values() if v)
                print(f"  delay-tested: {done}/{total}  可用: {alive}", flush=True)
    return delays


def make_unique_names(proxies):
    """给代理名称去重 (mihomo 不允许重名)"""
    used = {}
    for p in proxies:
        name = p.get("name") or f"{p['type']}-{p['server']}:{p['port']}"
        cnt = used.get(name, 0)
        used[name] = cnt + 1
        p["name"] = name if not cnt else f"{name}-{cnt}"
    return proxies


CN_NAME_RE = re.compile(r"🇨🇳|中国|大陆|_CN_|CN_|->CN|CN->|CN_中国")


def is_cn_node(p):
    """按名称判断节点是否为中国 (CN) 节点"""
    name = p.get("name") or p.get("_name") or ""
    return bool(CN_NAME_RE.search(name))


# 内置广告拦截兜底规则 (ACL4SSR 拉取失败时使用)
FALLBACK_RULES = [
    "DOMAIN-SUFFIX,doubleclick.net,REJECT",
    "DOMAIN-SUFFIX,googlesyndication.com,REJECT",
    "DOMAIN-SUFFIX,googleadservices.com,REJECT",
    "DOMAIN-SUFFIX,adservice.google.com,REJECT",
    "DOMAIN-SUFFIX,adnxs.com,REJECT",
    "DOMAIN-SUFFIX,adsystem.com,REJECT",
    "DOMAIN-SUFFIX,taboola.com,REJECT",
    "DOMAIN-SUFFIX,outbrain.com,REJECT",
    "DOMAIN-SUFFIX,advertising.com,REJECT",
    "DOMAIN-SUFFIX,moatads.com,REJECT",
    "DOMAIN-SUFFIX,scorecardresearch.com,REJECT",
    "DOMAIN-SUFFIX,zedo.com,REJECT",
    "DOMAIN-SUFFIX,quantserve.com,REJECT",
    "DOMAIN-SUFFIX,exoclick.com,REJECT",
    "DOMAIN-SUFFIX,popads.net,REJECT",
]

PROXY_GROUP = "🚀 节点选择"

# mihomo 支持的规则类型 (ACL4SSR 列表里可能混有 URL-REGEX 等不支持的类型, 需过滤)
SUPPORTED_RULE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
    "IP-CIDR", "IP-CIDR6", "GEOIP", "GEOSITE",
    "PROCESS-NAME", "PROCESS-PATH", "DST-PORT", "SRC-PORT", "SRC-IP-CIDR",
    "NETWORK", "MATCH", "RULE-SET",
}


def fetch_acl4ssr_rules():
    """抓取 ACL4SSR Full+AdblockPlus 规则 (subconverter 格式, 内含 ruleset= 引用).
    按策略生成分流组: 拦截/净化/广告 -> REJECT, 其余策略 -> 对应代理分组 (无 DIRECT)。
    返回 (rules, group_names)。失败时返回内置兜底规则 + 空分组。"""
    import clash_node_tester as t

    def map_target(policy):
        # 国内媒体/哔哩哔哩 -> DIRECT (国内流媒体走直连; 走国外代理会因地区限制不可用)
        if policy in ("🌏 国内媒体", "📺 哔哩哔哩"):
            return "DIRECT"
        # 广告/拦截/净化/隐私类 -> REJECT
        if ("广告" in policy or "拦截" in policy or "净化" in policy
                or "隐私" in policy or "adblock" in policy.lower()
                or "privacy" in policy.lower()):
            return "REJECT"
        # ACL4SSR 的主组名 -> 我们的主组
        if policy == "🚀 节点选择":
            return PROXY_GROUP
        # 其余策略 -> 同名独立分流组 (无 DIRECT)
        return policy

    try:
        text = t.fetch_subscription(t.ACL4SSR_URL, timeout=60)
    except Exception:
        print("  [warn] ACL4SSR 规则拉取失败, 使用内置兜底规则", flush=True)
        return list(FALLBACK_RULES) + ["MATCH," + PROXY_GROUP], []

    rules = []
    group_names = []
    refs = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("ruleset="):
            continue
        body = line.split("ruleset=", 1)[1].split(",", 1)
        if len(body) != 2:
            continue
        policy, url = body[0].strip(), body[1].strip()
        refs.append((policy, url))

    print(f"  [i] ACL4SSR ruleset 引用 {len(refs)} 个规则文件", flush=True)
    for policy, url in refs:
        target = map_target(policy)
        if target not in ("REJECT", "DIRECT") and target not in group_names:
            group_names.append(target)
        if url.startswith("[]"):
            # subconverter 内联规则: ruleset=策略组,[]GEOIP,CN / []FINAL
            inline = url[2:].strip()
            if inline.upper().startswith("FINAL"):
                rules.append("MATCH," + PROXY_GROUP)
            elif inline.split(",", 1)[0].upper() in SUPPORTED_RULE_TYPES \
                    and inline.split(",", 1)[0].upper() not in ("GEOIP", "GEOSITE"):
                rules.append(inline + "," + target)
            continue
        try:
            sub = t.fetch_subscription(url, timeout=60)
        except Exception:
            print(f"  [warn] 规则文件拉取失败: {url.split('/')[-1]}", flush=True)
            continue
        n_before = len(rules)
        for rl in sub.splitlines():
            rl = rl.strip()
            if not rl or rl.startswith(("#", ";")):
                continue
            parts = [p.strip() for p in rl.split(",")]
            if len(parts) < 2:
                continue
            rt = parts[0].upper()
            if rt not in SUPPORTED_RULE_TYPES:
                continue          # 过滤 URL-REGEX 等 mihomo 不支持的规则
            if rt in ("GEOIP", "GEOSITE"):
                continue          # 需 mmdb/geodata, 本网络无法自动下载, 剔除 (国内IP已由IP-CIDR覆盖)
            if len(parts) >= 3:
                parts[2] = target          # 替换已有策略, 保留其后标志位 (如 no-resolve)
                rules.append(",".join(parts))
            else:
                rules.append(rl + "," + target)   # 2段格式: 补上分组
            if len(rules) >= 150000:
                break
        if len(rules) >= 150000:
            break
        print(f"    [ruleset] {url.split('/')[-1]:<28} +{len(rules)-n_before} 条 -> {target}", flush=True)

    # 去重 (保持顺序)
    seen, uniq = set(), []
    for r in rules:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    rules = uniq
    if not rules:
        rules = list(FALLBACK_RULES)
        group_names = []
    rules.append("MATCH," + PROXY_GROUP)
    print(f"  [OK] 已加载 ACL4SSR Full+AdblockPlus 规则 {len(rules)} 条, "
          f"分流组 {len(group_names)} 个 (仅国内媒体直连)", flush=True)
    return rules, group_names


def export_full_config(ok_nodes, out_path):
    """导出完整可用配置: proxies + 多分流组 + ACL4SSR 规则 (无 DIRECT)"""
    proxies = [{k: v for k, v in r["raw"].items() if k != "_source"} for r in ok_nodes]
    names = [p["name"] for p in proxies]
    rules, group_names = fetch_acl4ssr_rules()

    auto = {"name": "♻️ 自动选择", "type": "url-test",
            "url": "http://www.gstatic.com/generate_204", "interval": 300,
            "tolerance": 50, "proxies": names}
    main = {"name": PROXY_GROUP, "type": "select",
            "proxies": ["♻️ 自动选择"] + names}
    groups = [main, auto]
    for g in group_names:
        if g not in (PROXY_GROUP, "♻️ 自动选择"):
            groups.append({"name": g, "type": "select",
                           "proxies": ["♻️ 自动选择"] + names})

    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-filter": ["*.lan", "+.local", "*.localhost"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
            "fallback": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
            # 规则已不含 GEOIP, 关闭 geoip fallback-filter 以免 mihomo 启动时下载 MMDB
            "fallback-filter": {"geoip": False},
        },
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": rules,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    print(f"\nexported 完整配置: {out_path} ( {len(proxies)} 节点, {len(rules)} 条规则, "
          f"{len(groups)} 个分流组, 仅国内媒体直连 )", flush=True)


def export_simple_config(ok_nodes, out_path):
    """导出包含基础分流规则的配置: proxies + PROXY组 + GEOIP,CN直连 + MATCH代理"""
    proxies = [{k: v for k, v in r["raw"].items() if k != "_source"} for r in ok_nodes]
    names = [p["name"] for p in proxies]
    groups = [{"name": "PROXY", "type": "select", "proxies": names}]
    rules = [
        "GEOIP,CN,DIRECT",
        "MATCH,PROXY",
    ]
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": rules,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    print(f"\n导出配置: {out_path} ( {len(proxies)} 节点, 基础分流规则 GEOIP,CN -> DIRECT, 其余 -> PROXY )", flush=True)

def test_with_mihomo(proxies, out_path="mihomo_alive.yaml", health_timeout=300,
                     check_timeout_ms=2000, min_alive=3, exclude_cn=True):
    """核心: 生成配置 -> mihomo -t 预检 -> 启动内核并发健康检查 -> 读取延迟 -> 导出。
    check_timeout_ms: 单节点健康检查超时(毫秒), 超过即判死丢弃。
    min_alive: 按订阅来源过滤, 某订阅可用节点数 < min_alive 时整体剔除该订阅,
               并自动将该订阅源加入屏蔽列表 (blocked_subs.txt), 下次运行直接跳过。
    返回 (results, ok_list); ok_list 为延迟非空且通过来源过滤的节点。"""
    if not proxies:
        print("no proxies!"); return [], []
    rejected_sources = set()
    build_config(proxies, check_timeout_ms=check_timeout_ms)

    # 预检: mihomo -t 逐轮校验, 自动剔除报错的代理 (mihomo 索引从 1 开始)
    while True:
        check = subprocess.run(["mihomo.exe", "-t", "-d", WORKDIR, "-f",
                                os.path.join(WORKDIR, "config.yaml")],
                               capture_output=True, text=True, timeout=60)
        err = check.stdout + check.stderr
        if check.returncode == 0:
            break
        m = re.search(r"proxy (\d+):", err)
        if not m:
            print("config test FAILED (无法定位问题代理):")
            print(err[-1200:])
            return [], []
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(proxies):
            bad = proxies.pop(idx)
            line = err.strip().splitlines()[-1] if err.strip() else err
            print(f"  [drop] #{idx+1} {bad.get('name')} ({bad.get('type')}): {line[:90]}", flush=True)
            build_config(proxies)
        else:
            print("config test FAILED (索引越界):")
            print(err[-1200:])
            return [], []
    print("config test OK, proxies:", len(proxies), flush=True)

    with open(os.path.join(WORKDIR, "run.log"), "w") as lf:
        proc = subprocess.Popen(["mihomo.exe", "-d", WORKDIR, "-f",
                                 os.path.join(WORKDIR, "config.yaml")],
                                stdout=lf, stderr=lf)
    print("mihomo started pid", proc.pid, flush=True)

    try:
        # 等 API 就绪
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                requests.get(API + "/proxies", timeout=5)
                break
            except Exception:
                time.sleep(1)

        # 并发 /delay 实测 (150 路并发, 远快于内核自动健康检查)
        print(f"  并发测速中 (150路, 超时 {check_timeout_ms}ms) ...", flush=True)
        delays = parallel_delay_test(proxies, timeout_ms=check_timeout_ms, concurrency=150)

        results = []
        for p in proxies:
            results.append({"name": p["name"], "type": p["type"], "server": p["server"],
                            "port": p["port"], "delay": delays.get(p["name"]), "raw": p})

        ok = [r for r in results if r["delay"]]
        ok.sort(key=lambda r: r["delay"])

        # ---- 按订阅来源过滤: 可用节点过少的订阅整体剔除 ----
        if min_alive > 1 and any(r.get("_source") or r["raw"].get("_source") for r in ok):
            from collections import defaultdict
            by_src = defaultdict(list)
            for r in ok:
                src = r.get("_source") or r["raw"].get("_source") or "(未知)"
                by_src[src].append(r)
            keep, dropped = [], []
            for src, lst in sorted(by_src.items(), key=lambda x: -len(x[1])):
                if len(lst) >= min_alive:
                    keep.extend(lst)
                else:
                    dropped.append((src, len(lst)))
                    if src != "(未知)":
                        rejected_sources.add(src)
            if dropped:
                print(f"\n  --- 剔除可用节点过少的订阅 (可用数 < {min_alive}) ---", flush=True)
                for src, c in dropped:
                    print(f"    [剔除] 可用 {c} 个: {src[:110]}", flush=True)
                print(f"  剔除后保留 {len(keep)} 个节点 (原 {len(ok)})", flush=True)
                print(f"  [屏蔽] 将 {len(rejected_sources)} 个低质量订阅源加入屏蔽列表", flush=True)
            ok = sorted(keep, key=lambda r: r["delay"])

        # ---- 剔除 CN 节点 ----
        if exclude_cn:
            cn_nodes = [r for r in ok if is_cn_node(r["raw"])]
            if cn_nodes:
                print(f"\n  --- 剔除 CN 节点 ({len(cn_nodes)} 个) ---", flush=True)
                for r in cn_nodes[:10]:
                    print(f"    [剔除CN] {r['raw'].get('name')}: {r['server']}:{r['port']}", flush=True)
                if len(cn_nodes) > 10:
                    print(f"    ... 等共 {len(cn_nodes)} 个", flush=True)
                ok = [r for r in ok if not is_cn_node(r["raw"])]

        print("\n==== mihomo 实测结果 ====", flush=True)
        print("total:", len(results), " alive:", len(ok), flush=True)
        print(f"\n  {'延迟ms':>7}  {'类型':<9}  {'server':<30}  {'port':<6}  name")
        for r in ok[:50]:
            print(f"  {r['delay']:>6}  {r['type']:<9}  {r['server'][:30]:<30}  {r['port']:<6}  {r['name'][:40]}", flush=True)

        export_simple_config(ok, out_path)

        # 把低质量订阅源写入屏蔽列表 (合并已有记录, 去重后保存)
        if rejected_sources:
            existing = set()
            if os.path.exists(BLOCKED_FILE):
                try:
                    with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
                        existing = {line.strip() for line in f if line.strip()}
                except Exception:
                    existing = set()
            merged = sorted(existing | rejected_sources)
            with open(BLOCKED_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(merged))
            print(f"[OK] 屏蔽列表已更新: {BLOCKED_FILE} (共 {len(merged)} 条)", flush=True)

        return results, ok
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def run():
    quick = "--quick" in sys.argv
    min_alive = 3
    exclude_cn = "--keep-cn" not in sys.argv
    for i, a in enumerate(sys.argv):
        if a == "--min-alive" and i + 1 < len(sys.argv):
            try:
                min_alive = max(int(sys.argv[i + 1]), 1)
            except ValueError:
                pass
    if quick:
        with open("alive_nodes.yaml", "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        raw = data.get("proxies", [])
        proxies = []
        for p in raw:
            d = sanitize(p)
            if d:
                d["_source"] = ""   # quick 模式无来源信息, 跳过来源过滤
                proxies.append(d)
        proxies = make_unique_names(proxies)
        print("quick mode: alive_nodes.yaml proxies:", len(proxies))
    else:
        print("loading all nodes ...", flush=True)
        nodes = load_nodes_full()
        proxies = []
        for n in nodes:
            d = sanitize(n.get("raw"))
            if d:
                d["_source"] = n.get("source", "")
                proxies.append(d)
        proxies = make_unique_names(proxies)
        print("proxies for mihomo:", len(proxies), flush=True)
    test_with_mihomo(proxies,
                     out_path="mihomo_alive_quick.yaml" if quick else "mihomo_alive.yaml",
                     min_alive=min_alive, exclude_cn=exclude_cn)


if __name__ == "__main__":
    run()

