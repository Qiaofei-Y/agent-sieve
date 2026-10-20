#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve S3 — 合并层：S0(DNS) + S2(TLS) 统一研判
==============================================

把 S0 的 DNS 侧信号和 S2 的 TLS/连接侧信号按设备合并，套用 sieve-verify 跑出来的
研判规则（不是两分相加），输出统一告警。核心规则：

  · 以 S2 为主判（TLS 层精确率最高）：JA4 判为脚本 → 告警。
  · S0 作补召回：抓 S2 没有 TLS 记录的场景（如纯 DoH 绕过）。
  · 需「≥2 条独立信号族」或「S2 脚本确认」才告警——不让 S0 单信号单独触发。
  · 人类用 LLM 的护栏：唯一证据是『连了 AI 域名』且 TLS 显示是浏览器 → 降为观察。
  · 两层同时命中同一设备 = 高置信。

直接 import 真实的 S0/S2 打分代码，保证与各自独立运行一致（单一事实源）。

用法：
    python3 sieve_s3.py --demo               # 合并两边的合成数据，Mac 上即可跑
    python3 sieve_s3.py --observe            # 读真实 Pi-hole 库 + Zeek 日志，只打印
    python3 sieve_s3.py --alert              # 告警级设备推 Telegram

仅用于你拥有或已获授权的网络。
"""

import argparse
import importlib.util
import json
import os
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
STATE_FILE = os.path.join(HERE, "sieve_s3_state.json")
S0_DIR = os.path.join(HERE, "..", "sieve-s0")
S2_DIR = os.path.join(HERE, "..", "sieve-s2")

# 信号 → 独立信号族（同族证据不重复计数）
FAMILY = {
    "LLM API": "llm", "Agent 基础设施": "llm", "首次出现敏感域名": "llm",
    "非浏览器 JA4": "script",
    "规律回连 beaconing": "beacon",
    "大体量外发": "egress",
    "域名扇出爆发": "fanout", "外连扇出爆发": "fanout",
    "DoH 绕过": "doh",
}

LEVEL_ORDER = {"告警": 0, "观察": 1, "正常": 2, "免分": 3}


def load_module(name, path):
    if not os.path.exists(path):
        sys.exit("找不到被测模块 %s（需与 sieve-s0 / sieve-s2 同级放置）" % path)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_config(path):
    cfg = {
        "pihole_db": "/etc/pihole/pihole-FTL.db",
        "zeek_logs_dir": "/opt/zeek/logs/current",
        "domains_file": os.path.join(S0_DIR, "domains.txt"),
        "fingerprints_file": os.path.join(S2_DIR, "ja4_fingerprints.txt"),
        "window_minutes": 60,
        "telegram": {"token": "", "chat_id": ""},
        "alert_cooldown_minutes": 180,
        "union_threshold": 55,
        "s2_automated_min": 40,
        "reputation_feed": "",
        "confirm_min_tenants": 3,
        "reputation_points": 30,
        "known_ai_clients": [],
    }
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                user = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            sys.exit("配置文件读取失败 %s: %s" % (path, e))
        for k, v in user.items():
            if k.startswith("_"):
                continue
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    cfg["telegram"]["token"] = os.environ.get("SIEVE_TG_TOKEN", cfg["telegram"].get("token", ""))
    cfg["telegram"]["chat_id"] = os.environ.get("SIEVE_TG_CHAT", cfg["telegram"].get("chat_id", ""))
    cfg["known_ai_clients"] = [c for c in cfg.get("known_ai_clients", [])
                               if isinstance(c, str) and not c.startswith("__")]
    return cfg


# ── 合并研判 ───────────────────────────────────────────────

def families_of(reasons):
    """从一层的 reasons 里取出有分值的独立信号族集合。"""
    return {FAMILY.get(lbl, lbl) for (lbl, pts, _d) in reasons if pts}


def decide(client, r0, r2, cfg):
    """合并一台设备的两层结果，返回研判 dict。"""
    known = (r0 and r0["known"]) or (r2 and r2["known"])
    s0_score = r0["score"] if r0 else 0
    s2_score = r2["score"] if r2 else 0
    combined = max(s0_score, s2_score)

    fam0 = families_of(r0["reasons"]) if r0 else set()
    fam2 = families_of(r2["reasons"]) if r2 else set()
    fams = fam0 | fam2
    s2_automated = "script" in fam2
    seen_both = bool(fam0) and bool(fam2)

    # 合并去重的信号说明（按族保留最先出现的细节）
    merged, seen_fam = [], set()
    for src, r in (("DNS", r0), ("TLS", r2)):
        if not r:
            continue
        for lbl, pts, detail in r["reasons"]:
            if not pts:
                continue
            fam = FAMILY.get(lbl, lbl)
            if fam in seen_fam:
                continue
            seen_fam.add(fam)
            merged.append((src, lbl, pts, detail))

    # ── 跨租户信誉（可选）──
    # 仅当配置了信誉源时附加；无 feed 时整段跳过，判定与之前逐字节一致（selftest 不受影响）。
    # 纯附加：只会增加 rep 信号族与分数，不会抑制任何原有判定，因此不会制造新漏报。
    feed = cfg.get("_feed")
    repmod = cfg.get("_rep_mod")
    rep_hits = []
    if feed and repmod and feed.get("entries") and not known:
        domains = []
        if r0 and r0.get("hit_domains"):
            for lst in r0["hit_domains"].values():
                domains.extend(lst)
        ja4s = r2.get("ja4_list", []) if r2 else []
        rep_hits = repmod.reputation_signal(feed, domains, ja4s,
                                            cfg.get("confirm_min_tenants", 3))
        if rep_hits:
            pts = cfg.get("reputation_points", 30)
            fams.add("rep")
            combined += pts
            ind = rep_hits[0][2]
            merged.append(("REP", "跨租户信誉命中", pts,
                           "%s · %d 租户确认(%s)" % (ind["indicator"], ind["tenants"], ind["category"])))

    # ── 研判规则（来自 sieve-verify）──
    if known:
        level = "免分"
    elif not fams and combined == 0:
        level = "正常"
    elif fams - {"rep"} == {"llm"} and not s2_automated:
        # 唯一证据是连了 AI 域名、且 TLS 看是浏览器 → 多半是人在用
        level = "观察" if combined >= cfg["union_threshold"] else "正常"
    elif s2_automated and combined >= cfg["s2_automated_min"]:
        level = "告警"
    elif len(fams) >= 2 and combined >= cfg["union_threshold"]:
        level = "告警"
    elif combined >= cfg["union_threshold"]:
        level = "观察"
    else:
        level = "正常"

    if level == "告警":
        # 两层命中、或跨租户信誉确认，都算高置信
        conf = "高" if (seen_both or rep_hits) else "中"
    elif level == "观察":
        conf = "低"
    else:
        conf = ""

    layers = []
    if fam0:
        layers.append("DNS")
    if fam2:
        layers.append("TLS")
    if rep_hits:
        layers.append("REP")

    return {"client": client, "level": level, "conf": conf, "combined": combined,
            "s0": s0_score, "s2": s2_score, "layers": layers, "known": known,
            "families": sorted(fams), "reasons": merged, "seen_both": seen_both}


def merge(r0_list, r2_list, cfg):
    by0 = {r["client"]: r for r in r0_list}
    by2 = {r["client"]: r for r in r2_list}
    clients = set(by0) | set(by2)
    out = [decide(c, by0.get(c), by2.get(c), cfg) for c in clients]
    out.sort(key=lambda d: (LEVEL_ORDER.get(d["level"], 9), -d["combined"]))
    return out


# ── 取数 ───────────────────────────────────────────────────

def gather(args, cfg, s0, s2):
    now = int(time.time())
    window_s = (args.window or cfg["window_minutes"]) * 60
    since = now - window_s
    if args.demo:
        s0_rows = s0.fetch_queries_demo(since, window_s)
        ssl_rows, conn_rows = s2.fetch_logs_demo(since, window_s)
        src = "合成数据（S0+S2 demo）"
    else:
        s0_rows = s0.fetch_queries_pihole(cfg["pihole_db"], since)
        ssl_rows, conn_rows = s2.fetch_logs(args.logs or cfg["zeek_logs_dir"], since)
        src = "真实数据（Pi-hole + Zeek）"
    return s0_rows, ssl_rows, conn_rows, src


# ── 输出 ───────────────────────────────────────────────────

C = {"red": "\033[31m", "yel": "\033[33m", "grn": "\033[32m",
     "cya": "\033[36m", "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}

def paint(on):
    return C if on else {k: "" for k in C}

def level_str(level, c):
    return {"告警": c["red"] + "告警" + c["off"],
            "观察": c["yel"] + "观察" + c["off"],
            "正常": c["grn"] + "正常" + c["off"],
            "免分": c["dim"] + "免分" + c["off"]}.get(level, level)

def print_report(merged, src, cfg, use_color):
    c = paint(use_color)
    n_alert = sum(1 for d in merged if d["level"] == "告警")
    n_watch = sum(1 for d in merged if d["level"] == "观察")
    print("\n%sSieve S3 · 合并研判%s   %s   设备=%d   告警=%d 观察=%d"
          % (c["bold"], c["off"], src, len(merged), n_alert, n_watch))
    print("规则: S2 主判 · ≥2 信号族或脚本确认才告警 · 并集阈值 %d · 两层命中=高置信"
          % cfg["union_threshold"])
    print("-" * 70)
    for d in merged:
        if d["level"] == "正常" and not d["reasons"]:
            continue
        badge = "".join("%s[%s]%s" % (c["cya"], l, c["off"]) for l in d["layers"]) or "—"
        both = " %s⚑两层命中%s" % (c["bold"], c["off"]) if d["seen_both"] and d["level"] == "告警" else ""
        conf = (" 置信=%s" % d["conf"]) if d["conf"] else ""
        print("\n%s%-16s%s %s%s  分数=%s%d%s(DNS %d/TLS %d)%s  %s%s"
              % (c["bold"], d["client"], c["off"], level_str(d["level"], c), conf,
                 c["bold"], d["combined"], c["off"], d["s0"], d["s2"], "", badge, both))
        for srcl, lbl, pts, detail in d["reasons"]:
            print("    %s%s +%-3d%s %s  %s%s%s"
                  % (c["dim"], srcl, pts, c["off"], lbl, c["dim"], detail, c["off"]))
    print("-" * 70)


# ── 状态 / Telegram ───────────────────────────────────────

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"last_alert": {}}

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)

def send_telegram(token, chat_id, text):
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text,
                                   "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=15) as resp:
        return resp.status == 200

def maybe_alert(merged, cfg, state):
    tg = cfg["telegram"]
    if not tg.get("token") or not tg.get("chat_id"):
        print("⚠ 未配置 Telegram（SIEVE_TG_TOKEN / SIEVE_TG_CHAT 或 config.json），跳过告警。")
        return
    now = int(time.time())
    cooldown = cfg["alert_cooldown_minutes"] * 60
    last = state.setdefault("last_alert", {})
    sent = 0
    for d in merged:
        if d["level"] != "告警":
            continue
        if now - int(last.get(d["client"], 0)) < cooldown:
            continue
        lines = ["🧭 <b>Sieve 合并告警</b>（置信=%s）" % d["conf"],
                 "设备 <code>%s</code> 分数 <b>%d</b>  层=%s"
                 % (d["client"], d["combined"], "+".join(d["layers"]) or "—"), ""]
        for srcl, lbl, pts, detail in d["reasons"]:
            lines.append("• [%s] +%d %s — %s" % (srcl, pts, lbl, detail))
        try:
            if send_telegram(tg["token"], tg["chat_id"], "\n".join(lines)):
                last[d["client"]] = now
                sent += 1
        except Exception as e:  # noqa: BLE001
            print("Telegram 发送失败 (%s): %s" % (d["client"], e))
    print("已推送 %d 条告警。" % sent)


# ── 主流程 ─────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Sieve S3 — S0+S2 合并研判")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--observe", action="store_true", help="只打印不告警")
    mode.add_argument("--alert", action="store_true", help="告警级设备推 Telegram")
    ap.add_argument("--demo", action="store_true", help="合并两边合成数据，无需 Pi-hole/Zeek")
    ap.add_argument("--window", type=int, default=None, help="回看分钟数")
    ap.add_argument("--logs", default=None, help="Zeek 日志目录（覆盖配置）")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)
    s0 = load_module("sieve_s0", os.path.join(S0_DIR, "sieve_s0.py"))
    s2 = load_module("sieve_s2", os.path.join(S2_DIR, "sieve_s2.py"))

    s0_rows, ssl_rows, conn_rows, src = gather(args, cfg, s0, s2)

    # 两层共用 known_ai_clients 与域名表
    cfg0 = s0.load_config(None); cfg0["known_ai_clients"] = cfg["known_ai_clients"]
    cfg2 = s2.load_config(None); cfg2["known_ai_clients"] = cfg["known_ai_clients"]
    dmap = s0.load_domains(cfg["domains_file"])
    fps = s2.load_fingerprints(cfg["fingerprints_file"])

    # 可选：加载跨租户信誉源（demo 下回退到示例源以演示效果）
    feed_path = cfg.get("reputation_feed") or ""
    if not feed_path and args.demo:
        example = os.path.join(HERE, "..", "sieve-rep", "feed.example.json")
        if os.path.exists(example):
            feed_path = example
    if feed_path and not os.path.isabs(feed_path):
        feed_path = os.path.normpath(os.path.join(HERE, "..", feed_path))
    if feed_path and os.path.exists(feed_path):
        repmod = load_module("reputation", os.path.join(HERE, "..", "sieve-rep", "reputation.py"))
        cfg["_rep_mod"] = repmod
        cfg["_feed"] = repmod.load_feed(feed_path)

    r0 = s0.score_clients(s0_rows, cfg0, dmap, baseline={})
    r2 = s2.score(ssl_rows, conn_rows, cfg2, dmap, fps)

    merged = merge(r0, r2, cfg)
    use_color = (not args.no_color) and sys.stdout.isatty()
    if args.demo:
        print("（demo：S0 %d 条 DNS，S2 %d ssl / %d conn）"
              % (len(s0_rows), len(ssl_rows), len(conn_rows)))
    print_report(merged, src, cfg, use_color)

    state = load_state()
    if args.alert:
        maybe_alert(merged, cfg, state)
    save_state(state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
