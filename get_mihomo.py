# -*- coding: utf-8 -*-
"""获取 mihomo 最新版本并下载 Windows amd64 内核 (走加速器)"""
import io, os, re, sys, zipfile
import requests
import clash_node_tester as t

t.GH_PROXY = os.environ.get("GH_PROXY", "https://666.hxlx.eu.org")
ACC = t.GH_PROXY

def get(url, timeout=120, stream=False):
    if ACC:
        url = ACC + "/" + url
    r = requests.get(url,
                     headers=t.HEADERS, timeout=timeout, stream=stream)
    r.raise_for_status()
    return r

# 1. 从 releases/latest 页面的重定向拿到最新 tag
r = get("https://github.com/MetaCubeX/mihomo/releases/latest", timeout=60)
tag = r.url.rstrip("/").split("/")[-1]
print("latest tag:", tag)
ver = tag.lstrip("v")

# 2. 组装下载地址并下载 zip
asset = f"mihomo-windows-amd64-v{ver}.zip"
dl = (f"https://github.com/MetaCubeX/mihomo/releases/download/{tag}/{asset}")
print("downloading:", dl)
r = get(dl, timeout=300)
data = r.content
print("downloaded bytes:", len(data))
with open("_mihomo_latest.zip", "wb") as f:
    f.write(data)

# 3. 解压 exe
with zipfile.ZipFile(io.BytesIO(data)) as z:
    names = z.namelist()
    exe = next((n for n in names if n.lower().endswith(".exe")), None)
    print("zip entries:", names[:6])
    if not exe:
        sys.exit("no exe found!")
    with z.open(exe) as src, open("mihomo.exe", "wb") as dst:
        dst.write(src.read())
print("extracted:", exe, "-> mihomo.exe", os.path.getsize("mihomo.exe") // 1024, "KB")

# 4. 验证能运行
import subprocess
out = subprocess.run(["mihomo.exe", "-v"], capture_output=True, text=True, timeout=30)
print("version check:", (out.stdout or out.stderr).strip()[:120])
