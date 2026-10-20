#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve Verify — 检测准确率评估 + 调参建议
=========================================

用一份带 ground-truth 标注的数据集（含"误报陷阱"），跑**真实的** S0 / S2
打分代码（直接 import，不重写），算出每台设备被判对/判错，输出：
  · 混淆矩阵 + 精确率/召回率/F1（S0、S2、以及两者并集）
  · 哪些良性设备被误报、是被哪条信号顶上去的
  · 阈值扫描：当前阈值 vs 最优阈值
  · 据此给出可执行的调参建议

数据来源二选一：
    python3 evaluate.py                 # 用内置 golden/ 标注集（Mac 上即可跑）
    python3 evaluate.py --from-live ... # 用你真实网络的 Pi-hole 库 + Zeek 日志 + 标注

内置标注集本身就能验证"方法成不成立"；真实数据才用来调你自家网络的参数。
仅用于你拥有或已获授权的网络。
"""

import argparse
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden")
S0_DIR = os.path.join(HERE, "..", "sieve-s0")
S2_DIR = os.path.join(HERE, "..", "sieve-s2")
DOMAINS = os.path.join(S0_DIR, "domains.txt")

# 内置标注集里预设的白名单设备
DEFAULT_KNOWN = ["10.0.0.50", "192.168.1.50"]


def load_module(name, path):
    if not os.path.exists(path):
        sys.exit("找不到被测模块 %s\n（需与 sieve-s0 / sieve-s2 同级放置）" % path)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ── 取数：内置 golden（按 t_offset 重基到 now）或真实 live ──

def load_golden(now):
    labels = json.load(open(os.path.join(GOLDEN, "labels.json"), encoding="utf-8"))
    dns = read_jsonl(os.path.join(GOLDEN, "dns.jsonl"))
    ssl = read_jsonl(os.path.join(GOLDEN, "ssl.jsonl"))
    conn = read_jsonl(os.path.join(GOLDEN, "conn.jsonl"))

    s0_rows = [(now - r["t_offset"], r["client"], r["domain"]) for r in dns]
    ssl_rows = [{"id.orig_h": r["client"], "id.resp_h": r["resp"],
                 "id.resp_p": 443, "server_name": r["sni"], "ja4": r["ja4"],
                 "ts": now - r["t_offset"]} for r in ssl]
    conn_rows = [{"id.orig_h": r["client"], "id.resp_h": r["resp"], "id.resp_p": 443,
                  "proto": "tcp", "orig_bytes": r["orig_bytes"],
                  "resp_bytes": r["resp_bytes"], "conn_state": "SF",
                  "ts": now - r["t_offset"]} for r in conn]
    return labels, s0_rows, ssl_rows, conn_rows, DEFAULT_KNOWN


def load_live(args, now, s0, s2):
    """真实数据：Pi-hole 库（S0）+ Zeek 日志（S2）+ 你的 labels.json。"""
    since = now - args.window * 60
    labels = json.load(open(args.labels, encoding="utf-8"))
    s0_rows = s0.fetch_queries_pihole(args.pihole_db, since)
    ssl_rows, conn_rows = s2.fetch_logs(args.zeek_logs, since)
    known = [c for c in labels if labels[c].get("truth") == "benign"
             and labels[c].get("known")]
    return labels, s0_rows, ssl_rows, conn_rows, known


# ── 评估 ───────────────────────────────────────────────────

def confusion(scores, labels, threshold):
    """scores: {client: int}; labels: {client:{truth}}. 返回 TP/FP/TN/FN 与明细。"""
    tp = fp = tn = fn = 0
    detail = {}
    for client, meta in labels.items():
        sc = scores.get(client, 0)
        flagged = sc >= threshold
        mal = meta["truth"] == "malicious"
        if mal and flagged:
            tp += 1; verdict = "TP"
        elif mal and not flagged:
            fn += 1; verdict = "FN"
        elif not mal and flagged:
            fp += 1; verdict = "FP"
        else:
            tn += 1; verdict = "TN"
        detail[client] = (verdict, sc)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "detail": detail}


def metrics(cm):
    tp, fp, fn = cm["tp"], cm["fp"], cm["fn"]
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def best_threshold(scores, labels, lo=5, hi=150, step=5):
    best = (0, 0.0)
    for t in range(lo, hi + 1, step):
        _p, _r, f1 = metrics(confusion(scores, labels, t))
        if f1 > best[1]:
            best = (t, f1)
    return best


# ── 输出 ───────────────────────────────────────────────────

C = {"red": "\033[31m", "yel": "\033[33m", "grn": "\033[32m",
     "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}

def paint(on):
    return C if on else {k: "" for k in C}


def reasons_for(results, client):
    for r in results:
        if r["client"] == client:
            return [(lbl, pts, d) for (lbl, pts, d) in r["reasons"] if pts]
    return []


def run(args):
    now = int(time.time())
    s0 = load_module("sieve_s0", os.path.join(S0_DIR, "sieve_s0.py"))
    s2 = load_module("sieve_s2", os.path.join(S2_DIR, "sieve_s2.py"))
    use_color = sys.stdout.isatty() and not args.no_color
    c = paint(use_color)

    if args.from_live:
        labels, s0_rows, ssl_rows, conn_rows, known = load_live(args, now, s0, s2)
        src = "真实数据（Pi-hole + Zeek）"
    else:
        labels, s0_rows, ssl_rows, conn_rows, known = load_golden(now)
        src = "内置标注集 golden/"

    # 配置：取两模块默认值，注入白名单与共享域名表
    cfg0 = s0.load_config(None); cfg0["known_ai_clients"] = known
    cfg2 = s2.load_config(None); cfg2["known_ai_clients"] = known
    dmap = s0.load_domains(DOMAINS)
    fps = s2.load_fingerprints(cfg2["fingerprints_file"])

    # 跑真实打分代码
    r0 = s0.score_clients(s0_rows, cfg0, dmap, baseline={})
    r2 = s2.score(ssl_rows, conn_rows, cfg2, dmap, fps)
    sc0 = {r["client"]: r["score"] for r in r0}
    sc2 = {r["client"]: r["score"] for r in r2}
    scU = {cl: max(sc0.get(cl, 0), sc2.get(cl, 0)) for cl in labels}  # 并集=取高分

    thr = args.threshold
    cm0, cm2, cmU = (confusion(sc0, labels, thr), confusion(sc2, labels, thr),
                     confusion(scU, labels, thr))

    print("\n%s===== Sieve Verify 评估报告 =====%s" % (c["bold"], c["off"]))
    print("数据源：%s   设备=%d   阈值=%d" % (src, len(labels), thr))

    # 逐设备判定
    print("\n%s逐设备判定%s（truth → S0 / S2 / 并集）" % (c["bold"], c["off"]))
    print("-" * 72)
    order = sorted(labels, key=lambda x: labels[x]["truth"] + x)
    for cl in order:
        m = labels[cl]
        v0 = cm0["detail"][cl]; v2 = cm2["detail"][cl]; vU = cmU["detail"][cl]
        truth_col = c["red"] if m["truth"] == "malicious" else c["grn"]

        def cell(v):
            verdict, sc = v
            col = c["grn"] if verdict in ("TP", "TN") else c["red"]
            return "%s%s%s %3d" % (col, verdict, c["off"], sc)

        print("%s%-11s%s %s%-9s%s │ %s │ %s │ %s  %s%s%s"
              % (c["bold"], cl, c["off"], truth_col, m["truth"], c["off"],
                 cell(v0), cell(v2), cell(vU), c["dim"], m["scenario"], c["off"]))
    print("-" * 72)
    print("%sTP%s=命中真坏  %sTN%s=正确放行  %sFP%s=误报  %sFN%s=漏报"
          % (c["grn"], c["off"], c["grn"], c["off"], c["red"], c["off"], c["red"], c["off"]))

    # 指标
    print("\n%s指标 @ 阈值 %d%s" % (c["bold"], thr, c["off"]))
    hdr = "%-10s %4s %4s %4s %4s   %6s %6s %6s" % ("检测层", "TP", "FP", "TN", "FN", "精确率", "召回率", "F1")
    print(hdr); print("-" * len(hdr))
    for name, cm in [("S0 (DNS)", cm0), ("S2 (TLS)", cm2), ("并集 S0∪S2", cmU)]:
        p, r, f1 = metrics(cm)
        print("%-10s %4d %4d %4d %4d   %5.0f%% %5.0f%% %5.2f"
              % (name, cm["tp"], cm["fp"], cm["tn"], cm["fn"], p * 100, r * 100, f1))

    # 误报归因
    print("\n%s误报归因%s（被误判的良性设备是哪条信号顶上去的）" % (c["bold"], c["off"]))
    any_fp = False
    for name, cm, results in [("S0", cm0, r0), ("S2", cm2, r2)]:
        for cl, (verdict, sc) in cm["detail"].items():
            if verdict == "FP":
                any_fp = True
                rs = reasons_for(results, cl)
                why = "；".join("%s+%d" % (lbl, pts) for lbl, pts, _ in rs) or "（累加）"
                print("  %s[%s] %s (%d)%s  %s — %s"
                      % (c["red"], name, cl, sc, c["off"], labels[cl]["scenario"], why))
    if not any_fp:
        print("  （无误报）")

    # 阈值扫描
    print("\n%s阈值扫描%s（当前 vs 使 F1 最高）" % (c["bold"], c["off"]))
    for name, scores in [("S0", sc0), ("S2", sc2), ("并集", scU)]:
        bt, bf1 = best_threshold(scores, labels)
        _, _, cur = metrics(confusion(scores, labels, thr))
        flag = "  ← 当前非最优" if abs(bt - thr) > 0 and bf1 > cur + 1e-9 else ""
        print("  %-6s 当前阈值 %d → F1 %.2f   最优阈值 %d → F1 %.2f%s"
              % (name, thr, cur, bt, bf1, flag))

    print_recommendations(cm0, cm2, cmU, c)


def print_recommendations(cm0, cm2, cmU, c):
    print("\n%s调参建议%s" % (c["bold"], c["off"]))
    tips = []
    if cm0["fp"] > cm2["fp"]:
        tips.append("S0（纯 DNS）误报比 S2 多——人类在浏览器里用 LLM 会被 DNS 层误判；"
                    "这正是 S2（JA4 区分脚本/浏览器）的价值。合并时别让 S0 单独越阈值触发告警。")
    if cm2["fn"] > 0:
        tips.append("S2 存在漏报——多为无 TLS 记录的场景（如纯 DoH 绕过）；"
                    "靠 S0/DNS 侧补，说明两层必须并用。")
    if cmU["fp"] <= min(cm0["fp"], cm2["fp"]) and cmU["fn"] <= min(cm0["fn"], cm2["fn"]):
        tips.append("并集（取高分）同时拿到两层的召回——是合并的合理默认。")
    tips.append("把人类 LLM 使用设备加进 known_ai_clients，或要求"
                "『≥2 条信号』才告警，可进一步压 S0 的误报。")
    tips.append("用 --from-live 换上你真实网络的数据重跑本评估，再据此改各模块 config.json 的 weights/阈值。")
    for i, t in enumerate(tips, 1):
        print("  %d. %s" % (i, t))
    print()


def main():
    ap = argparse.ArgumentParser(description="Sieve Verify — 检测准确率评估")
    ap.add_argument("--threshold", type=int, default=50, help="告警阈值（默认 50）")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--from-live", action="store_true", help="用真实数据而非内置标注集")
    ap.add_argument("--pihole-db", default="/etc/pihole/pihole-FTL.db")
    ap.add_argument("--zeek-logs", default="/opt/zeek/logs/current")
    ap.add_argument("--labels", default="labels.json", help="真实数据的 ground-truth 标注")
    ap.add_argument("--window", type=int, default=60, help="真实数据回看分钟数")
    run(ap.parse_args())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
