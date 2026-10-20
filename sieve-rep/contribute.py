#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve Reputation — 贡献端：把本地可疑指标导出成"观测报告"
=========================================================

隐私优先、自愿参与。把你本地 Sieve **已判为可疑、且属于公共类别**的指标
（公共 LLM/爬虫域名、JA4 指纹）导出成一份 sighting report，交给聚合端并入信誉库。

**绝不导出**：内网域名、IP、设备标识、具体时间点、浏览历史、任何正常流量。
只导出"我这边见到了已知公共坏类别的指标"这一事实，粒度到月。

tenant_id 是本机生成的随机假名（存在 .tenant_id，不入库），用于聚合端跨租户去重，
不含任何可识别你的信息。

用法：
    python3 contribute.py --demo                    # 看导出长什么样 + 隐私过滤如何生效
    python3 contribute.py --in findings.json --out report.json
findings.json 格式：[{"kind":"domain|ja4","value":"...","category":"...","verdict":"..."}]
（可由各检测器的输出整理得到；category 见 reputation.CONTRIBUTABLE_CATEGORIES）

仅用于你拥有或已获授权的网络。
"""

import argparse
import json
import os
import secrets
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reputation as rep  # noqa: E402

TENANT_FILE = os.path.join(HERE, ".tenant_id")


def tenant_id():
    """本机稳定的随机假名；首次生成后复用。"""
    if os.path.exists(TENANT_FILE):
        try:
            with open(TENANT_FILE, encoding="utf-8") as f:
                t = f.read().strip()
            if t:
                return t
        except OSError:
            pass
    t = "t_" + secrets.token_hex(8)
    try:
        with open(TENANT_FILE, "w", encoding="utf-8") as f:
            f.write(t)
    except OSError:
        pass
    return t


def build_report(findings, tid, month):
    """过滤 + 构造报告。返回 (report, dropped)。dropped 用于向用户展示隐私过滤生效。"""
    kept, dropped = [], []
    seen = set()
    for item in findings:
        kind = item.get("kind")
        value = item.get("value")
        cat = item.get("category")
        verdict = item.get("verdict", "suspicious")
        reason = None
        if kind not in ("domain", "ja4") or not value:
            reason = "无效指标"
        elif cat not in rep.CONTRIBUTABLE_CATEGORIES:
            reason = "非公共类别（可能是内网/私有，拒绝导出）"
        elif verdict not in ("bad", "suspicious", "spoofed", "automated"):
            reason = "非可疑判定，不导出"
        if reason:
            dropped.append((kind, value, reason))
            continue
        key = rep.make_key(kind, value)
        if key in seen:
            continue
        seen.add(key)
        # 只保留指标本身 + 类别；JA4 只留结构部分；域名原样（已确认是公共类别）
        kept.append({"kind": kind, "value": rep.split_key(key)[1], "category": cat})
    report = {"schema": rep.SCHEMA_VERSION, "tenant_id": tid, "month": month,
              "sightings": kept}
    return report, dropped


DEMO_FINDINGS = [
    {"kind": "domain", "value": "ai-tools-hub.net", "category": "content_farm", "verdict": "bad"},
    {"kind": "domain", "value": "api.openai.com", "category": "llm_api", "verdict": "suspicious"},
    {"kind": "ja4", "value": "t13d0908h1_aaa_bbb", "category": "ja4_script", "verdict": "automated"},
    {"kind": "domain", "value": "devguide-pro.io", "category": "scraper", "verdict": "bad"},
    # —— 以下必须被隐私过滤丢弃 ——
    {"kind": "domain", "value": "nas.home.lan", "category": "internal", "verdict": "bad"},
    {"kind": "domain", "value": "git.corp.example.com", "category": "internal", "verdict": "suspicious"},
    {"kind": "domain", "value": "wiki.internal", "category": None, "verdict": "bad"},
]


def main():
    ap = argparse.ArgumentParser(description="Sieve 信誉贡献端（隐私优先导出）")
    ap.add_argument("--demo", action="store_true", help="用合成数据演示导出与隐私过滤")
    ap.add_argument("--in", dest="infile", help="findings.json 输入")
    ap.add_argument("--out", help="输出报告路径（默认打印到 stdout）")
    ap.add_argument("--month", default=time.strftime("%Y-%m"), help="月份粒度（默认本月）")
    args = ap.parse_args()

    if args.demo:
        findings = DEMO_FINDINGS
    elif args.infile:
        with open(args.infile, encoding="utf-8") as f:
            findings = json.load(f)
    else:
        sys.exit("需要 --demo 或 --in findings.json")

    report, dropped = build_report(findings, tenant_id(), args.month)

    print("Sieve 贡献端 · 假名 tenant=%s · 月份=%s" % (report["tenant_id"], report["month"]))
    print("导出 %d 条公共可疑指标；隐私过滤丢弃 %d 条：" % (len(report["sightings"]), len(dropped)))
    for kind, value, reason in dropped:
        print("  ✗ %-5s %-28s %s" % (kind, value, reason))
    print("—— 将导出 ——")
    for s in report["sightings"]:
        print("  ✓ %-5s %-28s [%s]" % (s["kind"], s["value"], s["category"]))

    blob = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob)
        print("已写入 %s（可提交给聚合端并入信誉库）" % args.out)
    elif not args.demo:
        print(blob)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
