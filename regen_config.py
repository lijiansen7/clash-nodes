# -*- coding: utf-8 -*-
"""重新生成 mihomo_alive.yaml (ACL4SSR 规则拉取失败时自动重试)"""
import time
import yaml
import mihomo_engine as me

d = yaml.safe_load(open("mihomo_alive.yaml", encoding="utf-8"))
proxies = d["proxies"]
ok_nodes = [{"raw": p} for p in proxies]

rules, groups = [], []
for attempt in range(6):
    rules, groups = me.fetch_acl4ssr_rules()
    if len(rules) > 1000:
        break
    print(f"  第{attempt + 1}次拉取失败({len(rules)}条), 3秒后重试 ...", flush=True)
    time.sleep(3)

me.export_full_config(ok_nodes, "mihomo_alive.yaml")

# 验证国内媒体 -> DIRECT
d2 = yaml.safe_load(open("mihomo_alive.yaml", encoding="utf-8"))
rules2 = d2["rules"]
media_direct = [r for r in rules2 if r.rsplit(",", 1)[-1].upper() == "DIRECT"]
print("\nDIRECT 规则数:", len(media_direct))
print("国内媒体 DIRECT 示例:", media_direct[:3])
print("分流组:", [g["name"] for g in d2["proxy-groups"]])
