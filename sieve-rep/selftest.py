#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve Reputation 回归自测：隐私过滤、跨租户去重、抗投毒、完整性、查询。
退出码非 0 表示回归。CI 跑这个。
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reputation as rep          # noqa: E402
import contribute as contrib      # noqa: E402

fails = []
def check(cond, msg):
    if not cond:
        fails.append(msg); print("  ✗", msg)
    else:
        print("  ✓", msg)

print("== 隐私过滤 ==")
report, dropped = contrib.build_report(contrib.DEMO_FINDINGS, "t_test", "2026-10")
kept_vals = {s["value"] for s in report["sightings"]}
check(len(report["sightings"]) == 4, "保留 4 条公共指标（实际 %d）" % len(report["sightings"]))
check("nas.home.lan" not in kept_vals and "git.corp.example.com" not in kept_vals
      and "wiki.internal" not in kept_vals, "三个内网域名全部被丢弃")

print("== 跨租户去重 + 抗投毒 ==")
reps = [{"tenant_id": "t%d" % i, "month": "2026-10",
         "sightings": [{"kind": "domain", "value": "farm.example", "category": "content_farm"}]}
        for i in range(4)]
reps.append({"tenant_id": "t_poison", "month": "2026-10",
             "sightings": [{"kind": "domain", "value": "farm.example", "category": "content_farm"}] * 200})
feed = rep.merge_reports(reps, confirm_min_tenants=3)
ent = feed["entries"]["domain:farm.example"]
check(ent["tenants"] == 5, "5 个不同租户（4 正常 + 1 投毒，投毒只算 1 票；实际 %d）" % ent["tenants"])
check(ent["verdict"] == "bad", "达到阈值 → bad")

reps_lonely = [{"tenant_id": "t_one", "month": "2026-10",
                "sightings": [{"kind": "domain", "value": "lonely.example", "category": "scraper"}]}]
f2 = rep.merge_reports(reps_lonely, confirm_min_tenants=3)
check(f2["entries"]["domain:lonely.example"]["verdict"] == "suspicious",
      "单租户举报 → 仅 suspicious，不转 bad")

print("== 完整性校验 ==")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "feed.json")
    rep.save_feed(p, feed)
    loaded = rep.load_feed(p)
    check(loaded.get("_integrity_ok") is True, "保存后重载完整性校验通过")
    with open(p, encoding="utf-8") as f:
        tampered = f.read().replace("farm.example", "evil.example")
    with open(p, "w", encoding="utf-8") as f:
        f.write(tampered)
    loaded2 = rep.load_feed(p)
    check(loaded2.get("_integrity_ok") is False, "篡改后完整性校验能检出")

print("== 查询（reputation_signal） ==")
hits = rep.reputation_signal(feed, ["sub.farm.example"], [], confirm_min_tenants=3)
check(len(hits) == 1, "后缀命中 bad 指标（sub.farm.example → farm.example）")
none = rep.reputation_signal(feed, ["clean.example"], [], confirm_min_tenants=3)
check(not none, "未收录域名不命中")
below = rep.reputation_signal(f2, ["lonely.example"], [], confirm_min_tenants=3)
check(not below, "suspicious（未达阈值）不作为命中返回")

print("\nreputation selftest:", "❌ 失败 %d 项" % len(fails) if fails else "✅ 全部通过")
sys.exit(1 if fails else 0)
