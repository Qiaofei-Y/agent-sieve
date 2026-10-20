#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve S2 — TLS 指纹层检测器（Zeek + JA4）
==========================================

读 Zeek 的 ssl.log / conn.log，做三件 S0（纯 DNS）做不到的事：
  1. 用 JA4 指纹判断客户端是不是脚本（python/curl/go ≠ 真浏览器）；
  2. 从真实连接看回连节奏（beaconing），而非仅凭 DNS；
  3. 看外发体量（large egress）——可疑外泄。
再与同一份 LLM/agent 域名清单（复用 S0 的 domains.txt）关联打分、告警。

用法：
    python3 sieve_s2.py --demo               # 无需 Zeek，用合成日志看效果
    python3 sieve_s2.py --observe            # 读真实 Zeek 日志，只打印
    python3 sieve_s2.py --alert              # 超阈值推 Telegram
    python3 sieve_s2.py --logs /path/to/zeek/current --window 1440 --observe

JA4 判定优先级：ja4_fingerprints.txt 精确/前缀匹配 > 结构启发式。
启发式零配置即可工作；把自己网络里确认过的 JA4 填进表里可覆盖它。

仅用于你拥有或已获授权的网络。
"""

import argparse
import ipaddress
import json
import os
import re
import statistics
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
STATE_FILE = os.path.join(HERE, "sieve_s2_state.json")

CATEGORY_LABEL = {
    "llm_api": "LLM API",
    "agent_infra": "Agent 基础设施",
    "doh_resolver": "DoH 绕过",
}

JA4A_RE = re.compile(r"^([tq])(\d{2})([di])(\d{2})(\d{2})([a-z0-9]{2})")


# ── 配置 / 清单 ────────────────────────────────────────────

def load_config(path):
    cfg = {
        "zeek_logs_dir": "/opt/zeek/logs/current",
        "domains_file": os.path.join(HERE, "..", "sieve-s0", "domains.txt"),
        "fingerprints_file": os.path.join(HERE, "ja4_fingerprints.txt"),
        "window_minutes": 60,
        "local_nets": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
        "telegram": {"token": "", "chat_id": ""},
        "alert_threshold": 50, "review_threshold": 80, "alert_cooldown_minutes": 180,
        "weights": {
            "non_browser_ja4": 40, "llm_api": 30, "agent_infra": 20,
            "beaconing": 25, "large_egress": 20, "fanout_burst": 20, "doh_resolver": 15,
        },
        "fanout_threshold": 40, "beaconing_min_hits": 6, "beaconing_max_cv": 0.35,
        "large_egress_mb": 50, "known_ai_clients": [],
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
    cfg["telegram"]["token"] = os.environ.get("SIEVE_TG_TOKEN", cfg["telegram"].get("token", ""))
    cfg["telegram"]["chat_id"] = os.environ.get("SIEVE_TG_CHAT", cfg["telegram"].get("chat_id", ""))
    cfg["known_ai_clients"] = [c for c in cfg.get("known_ai_clients", [])
                               if isinstance(c, str) and not c.startswith("__")]
    return cfg


def load_domains(path):
    mapping, cat = {}, None
    if not os.path.exists(path):
        print("⚠ 找不到域名清单 %s，SNI 分类将跳过（建议指向 S0 的 domains.txt）" % path)
        return mapping
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                cat = line[1:-1].strip()
            elif cat:
                mapping[line.lower()] = cat
    return mapping


def match_category(domain, domain_map):
    d = (domain or "").lower().rstrip(".")
    if not d:
        return None
    if d in domain_map:
        return domain_map[d]
    for suffix, cat in domain_map.items():
        if d.endswith("." + suffix):
            return cat
    return None


def load_fingerprints(path):
    """返回 (exact{ja4:(verdict,label)}, prefixes[(prefix,verdict,label)])。"""
    exact, prefixes = {}, []
    if not path or not os.path.exists(path):
        return exact, prefixes
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            fp, verdict = parts[0], parts[1].lower()
            label = " ".join(parts[2:]) if len(parts) > 2 else ""
            if "_" in fp:
                exact[fp] = (verdict, label)
            else:
                prefixes.append((fp, verdict, label))
    return exact, prefixes


# ── JA4 判定 ───────────────────────────────────────────────

def classify_ja4(ja4, exact, prefixes):
    """返回 (verdict, why)。verdict ∈ browser | automated | unknown。"""
    if not ja4 or ja4 == "-":
        return "unknown", "无 JA4"

    if ja4 in exact:
        v, label = exact[ja4]
        return v, "标注表精确匹配：%s" % (label or v)
    for pre, v, label in prefixes:
        if ja4.startswith(pre):
            return v, "标注表前缀匹配：%s" % (label or v)

    # 结构启发式：解析 JA4_a
    m = JA4A_RE.match(ja4)
    if not m:
        return "unknown", "JA4_a 无法解析"
    _proto, tls_ver, sni, cipher_cnt, ext_cnt, alpn = m.groups()
    tls_ver = int(tls_ver)
    cipher_cnt = int(cipher_cnt)
    ext_cnt = int(ext_cnt)

    markers, notes = 0, []
    if alpn == "00":
        markers += 2; notes.append("无 ALPN")
    elif alpn == "h1":
        markers += 1; notes.append("仅 HTTP/1.1")
    if ext_cnt <= 8:
        markers += 2; notes.append("扩展极少(%d)" % ext_cnt)
    elif ext_cnt <= 11:
        markers += 1; notes.append("扩展偏少(%d)" % ext_cnt)
    if sni == "i":
        markers += 1; notes.append("无 SNI（按 IP 连）")
    if tls_ver <= 12:
        markers += 1; notes.append("仅 TLS<=1.2")

    if markers >= 3:
        return "automated", "启发式：疑似脚本（" + "、".join(notes) + "）"
    if markers == 2:
        return "automated", "启发式：偏自动化（" + "、".join(notes) + "）"
    if markers == 0 and ext_cnt >= 14 and alpn == "h2":
        return "browser", "启发式：结构像浏览器（扩展%d/h2）" % ext_cnt
    return "unknown", "启发式：无法确定（扩展%d/%s）" % (ext_cnt, alpn)


# ── 读 Zeek 日志 ──────────────────────────────────────────

def read_zeek_json(path, since_ts):
    """读一个 JSON-lines 的 Zeek 日志，返回 [dict,...]（ts >= since_ts）。"""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line[0] != "{":
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = rec.get("ts")
            if ts is None or float(ts) >= since_ts:
                rows.append(rec)
    return rows


def fetch_logs(logs_dir, since_ts):
    ssl_rows = read_zeek_json(os.path.join(logs_dir, "ssl.log"), since_ts)
    conn_rows = read_zeek_json(os.path.join(logs_dir, "conn.log"), since_ts)
    if not os.path.isdir(logs_dir):
        sys.exit("找不到 Zeek 日志目录: %s\n（没在跑 Zeek？用 --demo 看效果）" % logs_dir)
    return ssl_rows, conn_rows


# ── demo 合成日志 ─────────────────────────────────────────

def fetch_logs_demo(since_ts, window_s):
    now = int(time.time())
    base = now - window_s + 60
    ssl_rows, conn_rows = [], []

    def ssl(client, resp, sni, ja4, off):
        ssl_rows.append({"ts": base + off, "id.orig_h": client,
                         "id.resp_h": resp, "id.resp_p": 443,
                         "server_name": sni, "ja4": ja4})

    def conn(client, resp, off, ob=4000, rb=8000, n=1, step=0):
        for i in range(n):
            conn_rows.append({"ts": base + off + i * step, "id.orig_h": client,
                              "id.resp_h": resp, "id.resp_p": 443, "proto": "tcp",
                              "orig_bytes": ob, "resp_bytes": rb, "conn_state": "SF"})

    BROWSER = "t13d1516h2_8daaf6152771_02713d6af862"   # 扩展16/h2 → browser
    PYTHON  = "t13d0908h1_aaa1234bbbb2_ccc3456dddd4"   # 扩展8/仅h1 → automated
    CURL_IP = "t13i1107h2_aaa1111bbb22_ccc3333ddd44"   # 无SNI按IP连/扩展11 → automated

    # 正常浏览器设备 —— 低分
    ssl("192.168.1.11", "140.82.112.3", "github.com", BROWSER, 100)
    ssl("192.168.1.11", "17.253.144.10", "apple.com", BROWSER, 130)
    conn("192.168.1.11", "140.82.112.3", 100)

    # 已知 AI 客户端 —— 用 LLM 但在白名单，免分
    ssl("192.168.1.50", "160.79.104.10", "api.anthropic.com", BROWSER, 160)
    conn("192.168.1.50", "160.79.104.10", 160, ob=20000, rb=120000)

    # 影子 AI 外泄：python 脚本 → api.openai.com（非浏览器 + LLM）—— 高分
    ssl("192.168.1.23", "104.18.6.192", "api.openai.com", PYTHON, 200)
    conn("192.168.1.23", "104.18.6.192", 200, ob=900000, rb=30000)

    # 本地 agent：脚本指纹 + 域名爆发 + LLM —— 高分
    ssl("192.168.1.77", "1.1.1.1", "api.deepseek.com", PYTHON, 240)
    for i in range(52):
        conn("192.168.1.77", "203.0.113.%d" % (i % 254), 250 + i)

    # 回连 beaconing：等间隔连同一外部 IP —— 高分
    conn("192.168.1.99", "198.51.100.7", 10, ob=500, rb=500,
         n=12, step=int(window_s / 13))
    ssl("192.168.1.99", "198.51.100.7", "api.groq.com", PYTHON, 15)

    # 大体量外发：一条连接发出 >50MB —— 中分
    conn("192.168.1.33", "185.199.108.1", 300, ob=90 * 1024 * 1024, rb=5000)
    ssl("192.168.1.33", "185.199.108.1", "files.example.net", CURL_IP, 300)

    ssl_rows = [r for r in ssl_rows if r["ts"] >= since_ts]
    conn_rows = [r for r in conn_rows if r["ts"] >= since_ts]
    return ssl_rows, conn_rows


# ── 打分 ───────────────────────────────────────────────────

def is_local(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def is_known_client(client, known):
    c = (client or "").lower()
    return any(c == k.lower() or c.startswith(k.lower()) for k in known)


def coefficient_of_variation(ts_list):
    if len(ts_list) < 3:
        return None
    gaps = [b - a for a, b in zip(ts_list, ts_list[1:]) if b - a > 0]
    if len(gaps) < 2:
        return None
    mean = statistics.mean(gaps)
    return statistics.pstdev(gaps) / mean if mean else None


def score(ssl_rows, conn_rows, cfg, domain_map, fps):
    w = cfg["weights"]
    known = cfg["known_ai_clients"]
    nets = []
    for c in cfg["local_nets"]:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    exact, prefixes = fps

    per = defaultdict(lambda: {
        "ja4": {},                      # ja4 -> (verdict, why)
        "cat_hits": defaultdict(set),   # category -> {sni}
        "conn_ts": defaultdict(list),   # resp_h -> [ts]
        "resp_hosts": set(),
        "max_egress": 0,
        "egress_to": None,
    })

    # ssl.log：JA4 + SNI 分类
    for r in ssl_rows:
        client = r.get("id.orig_h", "?")
        if nets and not is_local(client, nets):
            continue  # 只看内网设备发起的
        p = per[client]
        ja4 = r.get("ja4") or "-"
        if ja4 not in p["ja4"]:
            p["ja4"][ja4] = classify_ja4(ja4, exact, prefixes)
        cat = match_category(r.get("server_name"), domain_map)
        if cat:
            p["cat_hits"][cat].add((r.get("server_name") or "").lower())

    # conn.log：回连节奏 + 扇出 + 外发体量
    for r in conn_rows:
        client = r.get("id.orig_h", "?")
        resp = r.get("id.resp_h", "?")
        if nets and not is_local(client, nets):
            continue
        if nets and is_local(resp, nets):
            continue  # 忽略内网→内网
        p = per[client]
        p["conn_ts"][resp].append(float(r.get("ts", 0)))
        p["resp_hosts"].add(resp)
        ob = int(r.get("orig_bytes") or 0)
        if ob > p["max_egress"]:
            p["max_egress"] = ob
            p["egress_to"] = resp

    results = []
    for client, p in per.items():
        known_client = is_known_client(client, known)
        s = 0
        reasons = []

        # 非浏览器 JA4（S2 的招牌信号）
        automated = [(fp, why) for fp, (v, why) in p["ja4"].items() if v == "automated"]
        if automated and not known_client:
            s += w["non_browser_ja4"]
            fp, why = automated[0]
            reasons.append(("非浏览器 JA4", w["non_browser_ja4"],
                            "%s · %s" % (fp.split("_")[0], why)))
        elif automated and known_client:
            reasons.append(("非浏览器 JA4", 0, "白名单设备，免分"))

        # SNI 命中 LLM / agent / DoH
        for cat, snis in p["cat_hits"].items():
            if known_client and cat in ("llm_api", "agent_infra"):
                reasons.append((CATEGORY_LABEL.get(cat, cat), 0,
                                "白名单设备，免分（%d 个域名）" % len(snis)))
                continue
            pts = w.get(cat, 0)
            s += pts
            reasons.append((CATEGORY_LABEL.get(cat, cat), pts,
                            "、".join(sorted(snis)[:4])))

        # beaconing：对某外部 IP 等间隔回连
        for resp, ts_list in p["conn_ts"].items():
            if len(ts_list) >= cfg["beaconing_min_hits"]:
                cv = coefficient_of_variation(sorted(ts_list))
                if cv is not None and cv <= cfg["beaconing_max_cv"]:
                    s += w["beaconing"]
                    reasons.append(("规律回连 beaconing", w["beaconing"],
                                    "%s · %d 次 · 间隔 CV=%.2f" % (resp, len(ts_list), cv)))
                    break

        # 域名/主机扇出
        fanout = len(p["resp_hosts"])
        if fanout >= cfg["fanout_threshold"]:
            s += w["fanout_burst"]
            reasons.append(("外连扇出爆发", w["fanout_burst"], "窗口内 %d 个外部主机" % fanout))

        # 大体量外发
        egress_mb = p["max_egress"] / (1024 * 1024)
        if egress_mb >= cfg["large_egress_mb"]:
            s += w["large_egress"]
            reasons.append(("大体量外发", w["large_egress"],
                            "单连 %.0f MB → %s" % (egress_mb, p["egress_to"])))

        if s > 0 or p["cat_hits"] or automated:
            ja4_list = sorted(set(fp.split("_")[0] for fp in p["ja4"] if fp != "-"))
            results.append({"client": client, "score": s, "known": known_client,
                            "reasons": reasons, "ja4_list": ja4_list})

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ── 状态 / 输出 / Telegram ────────────────────────────────

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


C = {"red": "\033[31m", "yel": "\033[33m", "grn": "\033[32m",
     "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}

def paint(on):
    return C if on else {k: "" for k in C}

def band(sc, cfg, c):
    if sc >= cfg["review_threshold"]:
        return c["red"] + "需查看" + c["off"]
    if sc >= cfg["alert_threshold"]:
        return c["yel"] + "告警" + c["off"]
    return c["grn"] + "正常" + c["off"]

def print_report(results, cfg, window_min, use_color):
    c = paint(use_color)
    print("\n%sSieve S2 · TLS 指纹检测报告%s   窗口=%d 分钟   设备=%d"
          % (c["bold"], c["off"], window_min, len(results)))
    print("阈值: 告警 ≥ %d · 需查看 ≥ %d" % (cfg["alert_threshold"], cfg["review_threshold"]))
    print("-" * 66)
    if not results:
        print("本窗口无命中。")
        return
    for r in results:
        tag = " %s[白名单]%s" % (c["dim"], c["off"]) if r["known"] else ""
        ja4s = ("  %sja4:%s%s" % (c["dim"], " ".join(r["ja4_list"][:3]), c["off"])
                if r["ja4_list"] else "")
        print("\n%s%-16s%s  分数=%s%3d%s  [%s]%s%s"
              % (c["bold"], r["client"], c["off"], c["bold"], r["score"], c["off"],
                 band(r["score"], cfg, c), tag, ja4s))
        for label, pts, detail in r["reasons"]:
            sign = "+%-3d" % pts if pts else "  · "
            print("    %s%s%s %s  %s%s%s"
                  % (c["dim"], sign, c["off"], label, c["dim"], detail, c["off"]))
    print("-" * 66)


def send_telegram(token, chat_id, text):
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text,
                                   "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=15) as resp:
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
        lines = ["🛰️ <b>Sieve S2 告警（TLS 层）</b>",
                 "设备 <code>%s</code> 分数 <b>%d</b>" % (r["client"], r["score"]), ""]
        for label, pts, detail in r["reasons"]:
            if pts:
                lines.append("• +%d %s — %s" % (pts, label, detail))
        try:
            if send_telegram(tg["token"], tg["chat_id"], "\n".join(lines)):
                last[r["client"]] = now
                sent += 1
        except Exception as e:  # noqa: BLE001
            print("Telegram 发送失败 (%s): %s" % (r["client"], e))
    print("已推送 %d 条告警。" % sent)


# ── 主流程 ─────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Sieve S2 — Zeek + JA4 TLS 指纹检测器")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--observe", action="store_true", help="只打印不告警")
    mode.add_argument("--alert", action="store_true", help="超阈值推 Telegram")
    ap.add_argument("--demo", action="store_true", help="用合成日志演示，无需 Zeek")
    ap.add_argument("--logs", default=None, help="Zeek 日志目录（覆盖配置）")
    ap.add_argument("--window", type=int, default=None, help="回看分钟数")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="配置文件路径")
    ap.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    args = ap.parse_args()

    cfg = load_config(args.config)
    domain_map = load_domains(cfg["domains_file"])
    fps = load_fingerprints(cfg["fingerprints_file"])
    window_min = args.window or cfg["window_minutes"]
    window_s = window_min * 60
    since_ts = int(time.time()) - window_s
    use_color = (not args.no_color) and sys.stdout.isatty()

    if args.demo:
        ssl_rows, conn_rows = fetch_logs_demo(since_ts, window_s)
        print("（demo 模式：合成 %d 条 ssl + %d 条 conn）" % (len(ssl_rows), len(conn_rows)))
    else:
        logs_dir = args.logs or cfg["zeek_logs_dir"]
        ssl_rows, conn_rows = fetch_logs(logs_dir, since_ts)

    results = score(ssl_rows, conn_rows, cfg, domain_map, fps)
    print_report(results, cfg, window_min, use_color)

    state = load_state()
    if args.alert:
        maybe_alert(results, cfg, state)
    save_state(state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
