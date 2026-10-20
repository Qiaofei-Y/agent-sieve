#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve S0 — 家庭网 AI / Agent 流量最小检测器
===========================================

从 Pi-hole 的 FTL 查询日志里，按设备找出 LLM API / agent 基础设施 / DoH 绕过
的痕迹，按规则打分，超阈值可推 Telegram 告警。纯标准库，树莓派上开箱即跑。

用法：
    python3 sieve_s0.py --demo                  # 无需 Pi-hole，用合成数据看效果
    python3 sieve_s0.py --observe               # 只观察打印，不告警（头两周用这个建基线）
    python3 sieve_s0.py --alert                 # 超阈值推 Telegram
    python3 sieve_s0.py --window 1440 --observe # 看过去 24 小时

配置见 config.example.json；密钥建议走环境变量 SIEVE_TG_TOKEN / SIEVE_TG_CHAT。

仅用于你拥有或已获授权的网络。
"""

import argparse
import json
import os
import sqlite3
import statistics
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
DOMAINS_FILE = os.path.join(HERE, "domains.txt")
STATE_FILE = os.path.join(HERE, "sieve_state.json")

CATEGORY_LABEL = {
    "llm_api": "LLM API",
    "agent_infra": "Agent 基础设施",
    "doh_resolver": "DoH 绕过",
}


# ── 配置与清单 ──────────────────────────────────────────────

def load_config(path):
    cfg = {
        "pihole_db": "/etc/pihole/pihole-FTL.db",
        "window_minutes": 60,
        "telegram": {"token": "", "chat_id": ""},
        "alert_threshold": 50,
        "review_threshold": 80,
        "alert_cooldown_minutes": 180,
        "weights": {
            "llm_api": 30, "agent_infra": 20, "doh_resolver": 15,
            "fanout_burst": 20, "beaconing": 25, "shadow_source": 20,
        },
        "fanout_threshold": 40,
        "beaconing_min_hits": 6,
        "beaconing_max_cv": 0.35,
        "known_ai_clients": [],
    }
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                user = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            sys.exit("配置文件读取失败 %s: %s\n（可从 config.example.json 重新复制）" % (path, e))
        if not isinstance(user, dict):
            sys.exit("配置文件格式错误（应为 JSON 对象）: %s" % path)
        for k, v in user.items():
            if k.startswith("_"):
                continue
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    # 环境变量覆盖密钥（最高优先级）
    cfg["telegram"]["token"] = os.environ.get("SIEVE_TG_TOKEN", cfg["telegram"].get("token", ""))
    cfg["telegram"]["chat_id"] = os.environ.get("SIEVE_TG_CHAT", cfg["telegram"].get("chat_id", ""))
    # 清理掉示例里的注释项
    cfg["known_ai_clients"] = [c for c in cfg.get("known_ai_clients", [])
                               if isinstance(c, str) and not c.startswith("__")]
    return cfg


def load_domains(path):
    """返回 {domain_suffix: category}。"""
    mapping = {}
    cat = None
    if not os.path.exists(path):
        sys.exit("找不到域名清单: %s" % path)
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                cat = line[1:-1].strip()
                continue
            if cat:
                mapping[line.lower()] = cat
    return mapping


def match_category(domain, domain_map):
    """后缀匹配（带点边界）。返回分类名或 None。"""
    d = (domain or "").lower().rstrip(".")
    if d in domain_map:
        return domain_map[d]
    for suffix, cat in domain_map.items():
        if d.endswith("." + suffix):
            return cat
    return None


# ── 取数：Pi-hole 或 demo ──────────────────────────────────

def fetch_queries_pihole(db_path, since_ts):
    """返回 [(timestamp, client, domain), ...]，按时间升序。"""
    if not os.path.exists(db_path):
        sys.exit("找不到 Pi-hole 数据库: %s\n（在 Mac 上没有 Pi-hole？用 --demo 看效果）" % db_path)
    uri = "file:%s?mode=ro" % urllib.request.pathname2url(db_path)
    con = sqlite3.connect(uri, uri=True, timeout=10)
    try:
        cur = con.execute(
            "SELECT timestamp, client, domain FROM queries "
            "WHERE timestamp >= ? ORDER BY timestamp ASC",
            (since_ts,),
        )
        return [(int(t), c or "?", d or "?") for (t, c, d) in cur.fetchall()]
    finally:
        con.close()


def fetch_queries_demo(since_ts, window_s):
    """合成一批有代表性的查询，用于在没有 Pi-hole 的机器上演示。"""
    now = int(time.time())
    base = now - window_s + 60
    rows = []

    def add(client, domain, offset, n=1, step=0):
        for i in range(n):
            rows.append((base + offset + i * step, client, domain))

    # 正常设备：日常 SaaS，无 LLM —— 应为低分
    for i, dom in enumerate(["github.com", "apple.com", "icloud.com", "google.com", "netflix.com"]):
        add("192.168.1.11", dom, 100 + i * 7)

    # 已知 AI 客户端：大量 LLM，但在白名单里 —— 应被免分
    add("192.168.1.50", "api.anthropic.com", 200, n=20, step=30)
    add("192.168.1.50", "api.openai.com", 260, n=8, step=45)

    # 影子 AI：一台不该碰 LLM 的设备在发 api.openai.com —— 应高分
    add("192.168.1.23", "api.openai.com", 300, n=5, step=120)
    add("192.168.1.23", "oaistatic.com", 360)

    # 本地 agent：短时间域名大爆发 + LLM 调用 —— 应高分
    add("192.168.1.77", "api.deepseek.com", 400, n=6, step=15)
    for i in range(55):
        add("192.168.1.77", "crawl-target-%02d.example.net" % i, 410 + i)

    # DoH 绕过：某设备连 Cloudflare DoH —— 应中分
    add("192.168.1.88", "mozilla.cloudflare-dns.com", 500, n=3, step=90)

    # 回连/beaconing：极规律的等间隔 LLM 查询 —— 应触发 beaconing
    add("192.168.1.99", "api.groq.com", 50, n=10, step=int(window_s / 11))

    rows = [r for r in rows if r[0] >= since_ts]
    rows.sort(key=lambda r: r[0])
    return rows


# ── 打分 ───────────────────────────────────────────────────

def is_known_client(client, known):
    c = (client or "").lower()
    return any(c == k.lower() or c.startswith(k.lower()) for k in known)


def coefficient_of_variation(timestamps):
    if len(timestamps) < 3:
        return None
    gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < 2:
        return None
    mean = statistics.mean(gaps)
    if mean == 0:
        return None
    return statistics.pstdev(gaps) / mean


def score_clients(rows, cfg, domain_map, baseline):
    """返回按分数降序的设备结果列表。"""
    w = cfg["weights"]
    known = cfg["known_ai_clients"]

    # 按设备聚合
    per_client = defaultdict(lambda: {
        "all_domains": set(),
        "cat_hits": defaultdict(set),           # category -> {domain}
        "ts_by_domain": defaultdict(list),      # domain -> [ts]
    })
    for ts, client, domain in rows:
        pc = per_client[client]
        pc["all_domains"].add(domain)
        pc["ts_by_domain"][domain].append(ts)
        cat = match_category(domain, domain_map)
        if cat:
            pc["cat_hits"][cat].add(domain)

    results = []
    for client, pc in per_client.items():
        known_client = is_known_client(client, known)
        score = 0
        reasons = []       # (label, points, detail)
        hit_domains = {}   # category -> sorted domains

        for cat, domains in pc["cat_hits"].items():
            hit_domains[cat] = sorted(domains)
            # 已知 AI 客户端免 LLM/agent 分（但 DoH 仍计）
            if known_client and cat in ("llm_api", "agent_infra"):
                reasons.append((CATEGORY_LABEL.get(cat, cat), 0,
                                "白名单设备，免分（%d 个域名）" % len(domains)))
                continue
            pts = w.get(cat, 0)
            score += pts
            reasons.append((CATEGORY_LABEL.get(cat, cat), pts,
                            "、".join(sorted(domains)[:4]) + ("…" if len(domains) > 4 else "")))

        # 域名扇出爆发
        fanout = len(pc["all_domains"])
        if fanout >= cfg["fanout_threshold"]:
            score += w["fanout_burst"]
            reasons.append(("域名扇出爆发", w["fanout_burst"],
                            "窗口内 %d 个不同域名" % fanout))

        # beaconing：某 LLM/agent 域名等间隔重复
        for cat in ("llm_api", "agent_infra"):
            if known_client:
                continue
            for domain in pc["cat_hits"].get(cat, ()):
                ts_list = sorted(pc["ts_by_domain"][domain])
                if len(ts_list) >= cfg["beaconing_min_hits"]:
                    cv = coefficient_of_variation(ts_list)
                    if cv is not None and cv <= cfg["beaconing_max_cv"]:
                        score += w["beaconing"]
                        reasons.append(("规律回连 beaconing", w["beaconing"],
                                        "%s · %d 次 · 间隔 CV=%.2f" % (domain, len(ts_list), cv)))
                        break
            else:
                continue
            break

        # shadow source：相对基线首次出现的 LLM/agent 域名
        if not known_client:
            seen = set(baseline.get(client, []))
            new_sensitive = []
            for cat in ("llm_api", "agent_infra"):
                for domain in pc["cat_hits"].get(cat, ()):
                    if domain not in seen:
                        new_sensitive.append(domain)
            if new_sensitive:
                score += w["shadow_source"]
                reasons.append(("首次出现敏感域名", w["shadow_source"],
                                "、".join(sorted(set(new_sensitive))[:3])))

        if score > 0 or hit_domains:
            results.append({
                "client": client,
                "score": score,
                "known": known_client,
                "reasons": reasons,
                "hit_domains": hit_domains,
                "fanout": fanout,
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ── 基线 / 状态 ────────────────────────────────────────────

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"baseline": {}, "last_alert": {}}


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)


def update_baseline(state, rows, domain_map):
    """把本轮见到的敏感域名并入每台设备的基线。"""
    base = state.setdefault("baseline", {})
    for _ts, client, domain in rows:
        if match_category(domain, domain_map) in ("llm_api", "agent_infra"):
            lst = base.setdefault(client, [])
            if domain not in lst:
                lst.append(domain)
    return state


# ── 输出 ───────────────────────────────────────────────────

C = {"red": "\033[31m", "yel": "\033[33m", "grn": "\033[32m",
     "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}

def paint(enabled):
    return C if enabled else {k: "" for k in C}

def band(score, cfg, c):
    if score >= cfg["review_threshold"]:
        return c["red"] + "需查看" + c["off"]
    if score >= cfg["alert_threshold"]:
        return c["yel"] + "告警" + c["off"]
    return c["grn"] + "正常" + c["off"]

def print_report(results, cfg, window_min, use_color):
    c = paint(use_color)
    print("\n%sSieve S0 · 信源检测报告%s   窗口=%d 分钟   设备=%d"
          % (c["bold"], c["off"], window_min, len(results)))
    print("阈值: 告警 ≥ %d · 需查看 ≥ %d" % (cfg["alert_threshold"], cfg["review_threshold"]))
    print("-" * 64)
    if not results:
        print("本窗口无命中。")
        return
    for r in results:
        tag = " %s[白名单]%s" % (c["dim"], c["off"]) if r["known"] else ""
        print("\n%s%-18s%s  分数=%s%3d%s  [%s]%s"
              % (c["bold"], r["client"], c["off"],
                 c["bold"], r["score"], c["off"], band(r["score"], cfg, c), tag))
        for label, pts, detail in r["reasons"]:
            sign = "+%-3d" % pts if pts else "  · "
            print("    %s%s%s %s  %s%s%s"
                  % (c["dim"], sign, c["off"], label, c["dim"], detail, c["off"]))
    print("-" * 64)


# ── Telegram ───────────────────────────────────────────────

def send_telegram(token, chat_id, text):
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    data = urllib.parse.urlencode({
        "chat_id": chat_id, "text": text,
        "parse_mode": "HTML", "disable_web_page_preview": "true",
    }).encode()
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status == 200


def maybe_alert(results, cfg, state):
    tg = cfg["telegram"]
    if not tg.get("token") or not tg.get("chat_id"):
        print("⚠ 未配置 Telegram（SIEVE_TG_TOKEN / SIEVE_TG_CHAT 或 config.json），跳过告警。")
        return
    now = int(time.time())
    cooldown = cfg["alert_cooldown_minutes"] * 60
    last = state.setdefault("last_alert", {})
    sent = 0
    for r in results:
        if r["score"] < cfg["alert_threshold"] or r["known"]:
            continue
        if now - int(last.get(r["client"], 0)) < cooldown:
            continue
        lines = ["🛡️ <b>Sieve S0 告警</b>",
                 "设备 <code>%s</code> 分数 <b>%d</b>" % (r["client"], r["score"]), ""]
        for label, pts, detail in r["reasons"]:
            if pts:
                lines.append("• +%d %s — %s" % (pts, label, detail))
        try:
            if send_telegram(tg["token"], tg["chat_id"], "\n".join(lines)):
                last[r["client"]] = now
                sent += 1
        except Exception as e:  # noqa: BLE001 — 告警失败不应中断巡检
            print("Telegram 发送失败 (%s): %s" % (r["client"], e))
    print("已推送 %d 条告警。" % sent)


# ── 主流程 ─────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Sieve S0 — 家庭网 AI/Agent 流量最小检测器")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--observe", action="store_true", help="只打印不告警（建基线用，默认模式）")
    mode.add_argument("--alert", action="store_true", help="超阈值推 Telegram")
    ap.add_argument("--demo", action="store_true", help="用合成数据演示，无需 Pi-hole")
    ap.add_argument("--window", type=int, default=None, help="回看分钟数（覆盖配置）")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="配置文件路径")
    ap.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    ap.add_argument("--no-baseline-update", action="store_true", help="本轮不更新基线")
    args = ap.parse_args()

    cfg = load_config(args.config)
    domain_map = load_domains(DOMAINS_FILE)
    window_min = args.window or cfg["window_minutes"]
    window_s = window_min * 60
    since_ts = int(time.time()) - window_s
    use_color = (not args.no_color) and sys.stdout.isatty()

    if args.demo:
        rows = fetch_queries_demo(since_ts, window_s)
        print("（demo 模式：使用合成数据，共 %d 条查询）" % len(rows))
    else:
        rows = fetch_queries_pihole(cfg["pihole_db"], since_ts)

    state = load_state()
    baseline = state.get("baseline", {})
    results = score_clients(rows, cfg, domain_map, baseline)

    print_report(results, cfg, window_min, use_color)

    if args.alert:
        maybe_alert(results, cfg, state)

    # demo 不污染真实基线
    if not args.no_baseline_update and not args.demo:
        update_baseline(state, rows, domain_map)
    save_state(state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
