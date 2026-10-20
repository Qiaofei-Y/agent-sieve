#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve Reputation — 聚合端：把多份观测报告并成一份信誉源
=======================================================

把一堆 sighting report（来自不同装机点）按**跨租户去重计数**并成 feed.json：
一个指标被越多**不同租户**独立举报，信誉越硬；达到确认阈值即标为 bad。
这就是护城河的网络效应——越多人贡献，信誉源越准，所有消费端一起受益。

用法：
    python3 aggregate.py --demo                       # 演示网络效应：同一域名被 N 个租户举报后"转正"
    python3 aggregate.py --reports ./reports --out feed.json --confirm-min 3

抗投毒：同一 tenant 对同一指标只计一次；单租户单次贡献量封顶。
生产环境应对 feed.json 再加 GPG 签名分发（见 README）。

仅用于你拥有或已获授权的网络。
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reputation as rep  # noqa: E402


def load_reports(dir_path):
    reports = []
    for name in sorted(os.listdir(dir_path)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(dir_path, name), encoding="utf-8") as f:
                reports.append(json.load(f))
        except (json.JSONDecodeError, OSError) as e:
            print("⚠ 跳过 %s: %s" % (name, e))
    return reports


def demo_reports():
    """8 个租户的报告：ai-tools-hub.net 被 5 家举报（应转 bad），
    某脚本 JA4 被 4 家举报（bad），一个只被 1 家举报的域名（停留在 suspicious），
    外加一个投毒者把同一指标塞很多次（仍只算 1 票）。"""
    reps = []
    for i in range(5):
        reps.append({"tenant_id": "t_farm%d" % i, "month": "2026-10", "sightings": [
            {"kind": "domain", "value": "ai-tools-hub.net", "category": "content_farm"},
        ]})
    for i in range(4):
        reps.append({"tenant_id": "t_ja4%d" % i, "month": "2026-10", "sightings": [
            {"kind": "ja4", "value": "t13d0908h1_x_y", "category": "ja4_script"},
        ]})
    reps.append({"tenant_id": "t_lonely", "month": "2026-10", "sightings": [
        {"kind": "domain", "value": "maybe-bad.example", "category": "scraper"},
    ]})
    # 投毒者：同一域名刷 100 次，但只有 1 个 tenant_id → 只算 1 票
    reps.append({"tenant_id": "t_poison", "month": "2026-10",
                 "sightings": [{"kind": "domain", "value": "ai-tools-hub.net",
                                "category": "content_farm"}] * 100})
    return reps


def main():
    ap = argparse.ArgumentParser(description="Sieve 信誉聚合端")
    ap.add_argument("--demo", action="store_true", help="演示跨租户聚合与抗投毒")
    ap.add_argument("--reports", help="报告目录（内含多份 *.json）")
    ap.add_argument("--out", help="输出 feed.json 路径（默认打印摘要）")
    ap.add_argument("--confirm-min", type=int, default=3, help="标为 bad 所需的最少不同租户数")
    args = ap.parse_args()

    if args.demo:
        reports = demo_reports()
    elif args.reports:
        reports = load_reports(args.reports)
    else:
        sys.exit("需要 --demo 或 --reports <dir>")

    feed = rep.merge_reports(reports, confirm_min_tenants=args.confirm_min)
    entries = feed["entries"]
    bad = sum(1 for e in entries.values() if e["verdict"] == "bad")
    print("聚合 %d 份报告 → %d 个指标（bad=%d · 确认阈值=%d 租户）"
          % (len(reports), len(entries), bad, args.confirm_min))
    print("%-34s %-12s %-9s %6s %8s" % ("指标", "类别", "判定", "租户数", "举报次"))
    print("-" * 74)
    for key in sorted(entries, key=lambda k: (-entries[k]["tenants"], k)):
        e = entries[key]
        mark = "🔴" if e["verdict"] == "bad" else "🟡"
        print("%-34s %-12s %s %-7s %5d %8d"
              % (e["indicator"][:34], e["category"], mark, e["verdict"],
                 e["tenants"], e["sightings"]))

    if args.out:
        rep.save_feed(args.out, feed)
        print("\n已写入签名校验信誉源 %s（分发给各装机点消费）" % args.out)
    if args.demo:
        print("\n注意 t_poison 把 ai-tools-hub.net 刷了 100 次，但它只贡献 1 个租户票——"
              "该域名转 bad 靠的是 5 个不同租户，不是刷量。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
