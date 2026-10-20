#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve S1 — 爬虫真伪核验（公网服务访问日志）
=============================================

对暴露在公网的服务（反代 / NAS / 博客）的访问日志，找出**自称是 AI 爬虫**
（User-Agent 含 GPTBot / ClaudeBot / PerplexityBot 等）的请求，用厂商**官方公布
的 IP 段 JSON** 核验来源 IP 是否真的属于该厂商：

    UA 声称 GPTBot + IP 在官方段内   → verified（真爬虫）
    UA 声称 GPTBot + IP 不在官方段内 → spoofed （冒充，告警）
    取不到官方 IP 段                 → unverifiable（降级跳过，不崩）

厂商 IP 段 JSON 在运行时按 URL 拉取并本地缓存（见 config，带 urllib 超时与
失败降级），不硬编码任何 IP。可选 forward-confirmed rDNS（FCrDNS）作增强。

用法：
    python3 sieve_s1.py --demo                 # 无需真实日志，合成一段看效果
    python3 sieve_s1.py --observe              # 读真实日志，只打印不告警
    python3 sieve_s1.py --log /var/log/nginx/access.log --observe
    python3 sieve_s1.py --alert                # spoofed 超阈值推 Telegram
    python3 sieve_s1.py --log access.log --rdns --observe   # 附带 FCrDNS 增强

配置见 config.example.json；密钥建议走环境变量 SIEVE_TG_TOKEN / SIEVE_TG_CHAT。

仅用于你拥有或已获授权的网络。
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
DEFAULT_CACHE_DIR = os.path.join(HERE, ".cache")
STATE_FILE = os.path.join(HERE, "sieve_s1_state.json")

# 兜底 bot 清单：没有 config.json 时也能工作（URL 均为厂商官方公布地址）。
DEFAULT_BOTS = [
    {"name": "GPTBot", "vendor": "OpenAI", "ua_tokens": ["GPTBot"],
     "ip_json_urls": ["https://openai.com/gptbot.json"],
     "rdns_suffixes": [".openai.com"]},
    {"name": "OAI-SearchBot", "vendor": "OpenAI", "ua_tokens": ["OAI-SearchBot"],
     "ip_json_urls": ["https://openai.com/searchbot.json"],
     "rdns_suffixes": [".openai.com"]},
    {"name": "ChatGPT-User", "vendor": "OpenAI", "ua_tokens": ["ChatGPT-User"],
     "ip_json_urls": ["https://openai.com/chatgpt-user.json"],
     "rdns_suffixes": [".openai.com"]},
    {"name": "ClaudeBot", "vendor": "Anthropic",
     "ua_tokens": ["ClaudeBot", "Claude-Web", "anthropic-ai", "Claude-User", "Claude-SearchBot"],
     "ip_json_urls": ["https://claude.com/crawling/bots.json"],
     "rdns_suffixes": [".anthropic.com", ".claude.com"]},
    {"name": "PerplexityBot", "vendor": "Perplexity", "ua_tokens": ["PerplexityBot"],
     "ip_json_urls": ["https://www.perplexity.ai/perplexitybot.json"],
     "rdns_suffixes": [".perplexity.ai"]},
    {"name": "Perplexity-User", "vendor": "Perplexity", "ua_tokens": ["Perplexity-User"],
     "ip_json_urls": ["https://www.perplexity.ai/perplexity-user.json"],
     "rdns_suffixes": [".perplexity.ai"]},
]


# ── 配置 ───────────────────────────────────────────────────

def load_config(path):
    cfg = {
        "log_path": "/var/log/nginx/access.log",
        "cache_dir": DEFAULT_CACHE_DIR,
        "cache_ttl_hours": 24,
        "fetch_timeout_seconds": 10,
        "enable_rdns": False,
        "spoof_alert_threshold": 1,       # 单个 bot 的 spoofed 请求数达到即告警
        "alert_cooldown_minutes": 180,
        "telegram": {"token": "", "chat_id": ""},
        "bots": DEFAULT_BOTS,
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
    # 清掉示例里的注释项、留下有名字的 bot
    cfg["bots"] = [b for b in cfg.get("bots", [])
                   if isinstance(b, dict) and b.get("name") and b.get("ua_tokens")]
    if not cfg["bots"]:
        cfg["bots"] = DEFAULT_BOTS
    # cache_dir 支持相对路径（相对本目录）
    if not os.path.isabs(cfg["cache_dir"]):
        cfg["cache_dir"] = os.path.join(HERE, cfg["cache_dir"])
    return cfg


# ── 访问日志解析（combined / common）──────────────────────

# 兼容 combined（带 referer + UA）与 common（无末尾两段引号字段）。
LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_log_line(line):
    """解析一行访问日志。返回 dict 或 None（不匹配 / 无 UA）。"""
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    ua = m.group("ua")
    if ua is None:
        return None  # common 格式没有 UA，无法核验爬虫身份，跳过
    return {
        "ip": m.group("ip"),
        "time": m.group("time"),
        "request": m.group("request"),
        "status": m.group("status"),
        "ua": ua,
    }


def read_access_log(path):
    """逐行解析访问日志，返回带 UA 的记录列表。"""
    if not os.path.exists(path):
        sys.exit("找不到访问日志: %s\n（在本机没有真实日志？用 --demo 看效果）" % path)
    records = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_log_line(line)
            if rec:
                records.append(rec)
    return records


# ── UA 匹配 ────────────────────────────────────────────────

def build_token_index(bots):
    """返回 [(token_lower, bot), ...]，按 token 长度降序以便优先匹配更长 token。"""
    idx = []
    for bot in bots:
        for tok in bot.get("ua_tokens", []):
            if isinstance(tok, str) and tok:
                idx.append((tok.lower(), bot))
    idx.sort(key=lambda t: len(t[0]), reverse=True)
    return idx


def match_bot(ua, token_index):
    """UA 若自称某个受核验的 bot，返回其 bot 配置，否则 None。"""
    low = (ua or "").lower()
    for tok, bot in token_index:
        if tok in low:
            return bot
    return None


# ── 厂商官方 IP 段：拉取 + 缓存 + 解析 ─────────────────────

_IPISH = re.compile(r'^[0-9a-fA-F:.]+(/\d{1,3})?$')


def _try_network(s):
    """宽松地把字符串解析成 IP 网段；不是 IP/CIDR 就返回 None。"""
    s = s.strip()
    if not _IPISH.match(s):
        return None
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def extract_cidrs(obj):
    """从任意结构的厂商 JSON 里挖出所有 CIDR / IP。

    兼容多家不同格式：OpenAI 用 {"prefixes":[{"ipv4Prefix":...}]}，
    其他厂商可能是 {"prefixes":[{"ipv6Prefix":...}]} 或直接是字符串列表。
    不硬编码字段名——凡是键名含 prefix/cidr/ip 或值本身像 IP 的都收。
    """
    nets = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                kl = str(k).lower()
                if isinstance(v, str) and ("prefix" in kl or "cidr" in kl
                                           or kl in ("ip", "range", "address")):
                    n = _try_network(v)
                    if n:
                        nets.append(n)
                        continue
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            n = _try_network(o)
            if n:
                nets.append(n)

    walk(obj)
    return nets


def _cache_path(cache_dir, url):
    safe = re.sub(r'[^A-Za-z0-9._-]', "_", url)
    return os.path.join(cache_dir, safe[:150] + ".json")


def fetch_ranges_for_url(url, cfg, use_cache=True, refresh=False):
    """取单个 URL 的 IP 段。

    返回 (nets, source)，source ∈ {"cache", "network", "stale", None}。
    取不到（网络失败且无缓存）返回 ([], None)，调用方据此降级，不崩。
    """
    cache_dir = cfg["cache_dir"]
    ttl = cfg["cache_ttl_hours"] * 3600
    cpath = _cache_path(cache_dir, url)
    now = time.time()

    # 1) 命中新鲜缓存
    cached = None
    if use_cache and os.path.exists(cpath):
        try:
            with open(cpath, encoding="utf-8") as f:
                cached = json.load(f)
        except (json.JSONDecodeError, OSError):
            cached = None
        if cached and not refresh and (now - cached.get("fetched_at", 0) < ttl):
            nets = [ipaddress.ip_network(c) for c in cached.get("cidrs", [])]
            return nets, "cache"

    # 2) 拉网络
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sieve-s1/1.0"})
        with urllib.request.urlopen(req, timeout=cfg["fetch_timeout_seconds"]) as resp:
            raw = resp.read().decode("utf-8", "replace")
        data = json.loads(raw)
        nets = extract_cidrs(data)
        if use_cache:
            try:
                os.makedirs(cache_dir, exist_ok=True)
                tmp = cpath + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump({"url": url, "fetched_at": now,
                               "cidrs": [str(n) for n in nets]},
                              f, ensure_ascii=False, indent=2)
                os.replace(tmp, cpath)
            except OSError:
                pass  # 缓存写不进去不影响核验
        return nets, "network"
    except Exception as e:  # noqa: BLE001 — 任何网络/解析失败都降级，不中断
        # 3) 网络失败但有旧缓存 → 用旧的，总比没有强
        if cached and cached.get("cidrs"):
            print("⚠ 拉取失败，改用过期缓存 %s（%s）" % (url, e))
            nets = [ipaddress.ip_network(c) for c in cached.get("cidrs", [])]
            return nets, "stale"
        print("⚠ 拉取 IP 段失败，跳过核验 %s（%s）" % (url, e))
        return [], None


def load_bot_ranges(bots, cfg, use_cache=True, refresh=False):
    """为每个 bot 汇总其所有 URL 的 IP 段。

    返回 {bot_name: {"nets": [...], "ok": bool, "sources": [...]}}。
    ok=False 表示一个段都没取到 → 该 bot 的请求判为 unverifiable。
    """
    out = {}
    for bot in bots:
        nets, sources, any_ok = [], [], False
        for url in bot.get("ip_json_urls", []):
            got, src = fetch_ranges_for_url(url, cfg, use_cache=use_cache, refresh=refresh)
            if src is not None:
                any_ok = True
                sources.append(src)
            nets.extend(got)
        out[bot["name"]] = {"nets": nets, "ok": any_ok and bool(nets), "sources": sources}
    return out


# ── 核验 ───────────────────────────────────────────────────

def ip_in_nets(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        if addr.version == n.version and addr in n:
            return True
    return False


def forward_confirmed_rdns(ip, suffixes):
    """FCrDNS：PTR 命中厂商域名后缀，且正向解析能回到同一 IP。

    返回 (ok: bool, hostname: str|None)。任何失败都安静返回 False。
    """
    if not suffixes:
        return False, None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return False, None
    hl = host.lower().rstrip(".")
    if not any(hl.endswith(suf.lower().lstrip(".")) or hl.endswith(suf.lower())
               for suf in suffixes):
        return False, host
    try:
        infos = socket.getaddrinfo(host, None)
        resolved = {ai[4][0] for ai in infos}
    except (socket.gaierror, OSError):
        return False, host
    return (ip in resolved), host


def verify_records(records, bots, ranges, cfg, use_rdns=False):
    """核验所有自称爬虫的请求，按 bot 聚合结果。"""
    token_index = build_token_index(bots)
    groups = OrderedDict()
    for bot in bots:
        groups[bot["name"]] = {
            "vendor": bot.get("vendor", "?"),
            "verified": [], "spoofed": [], "unverifiable": [],
            "ok": ranges.get(bot["name"], {}).get("ok", False),
            "sources": ranges.get(bot["name"], {}).get("sources", []),
            "rdns_suffixes": bot.get("rdns_suffixes", []),
        }

    claimed = 0
    rdns_cache = {}
    for rec in records:
        bot = match_bot(rec["ua"], token_index)
        if not bot:
            continue
        claimed += 1
        g = groups[bot["name"]]
        entry = {"ip": rec["ip"], "request": rec["request"],
                 "status": rec["status"], "ua": rec["ua"], "time": rec["time"]}

        if not g["ok"]:
            g["unverifiable"].append(entry)
            continue

        inside = ip_in_nets(rec["ip"], ranges[bot["name"]]["nets"])

        if use_rdns and g["rdns_suffixes"]:
            key = (rec["ip"], bot["name"])
            if key not in rdns_cache:
                rdns_cache[key] = forward_confirmed_rdns(rec["ip"], g["rdns_suffixes"])
            ok, host = rdns_cache[key]
            entry["rdns_ok"] = ok
            entry["rdns_host"] = host

        if inside:
            g["verified"].append(entry)
        else:
            g["spoofed"].append(entry)

    return groups, claimed


# ── 状态（告警冷却）────────────────────────────────────────

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


# ── 输出 ───────────────────────────────────────────────────

C = {"red": "\033[31m", "yel": "\033[33m", "grn": "\033[32m",
     "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}

def paint(enabled):
    return C if enabled else {k: "" for k in C}


def _trim(s, n):
    s = s or ""
    return s if len(s) <= n else s[:n - 1] + "…"


def print_report(groups, claimed, total, use_color):
    c = paint(use_color)
    total_spoofed = sum(len(g["spoofed"]) for g in groups.values())
    total_verified = sum(len(g["verified"]) for g in groups.values())
    total_unver = sum(len(g["unverifiable"]) for g in groups.values())

    print("\n%sSieve S1 · 爬虫真伪核验报告%s   日志请求=%d   自称爬虫=%d"
          % (c["bold"], c["off"], total, claimed))
    print("合计: %sverified=%d%s · %sspoofed=%d%s · %sunverifiable=%d%s"
          % (c["grn"], total_verified, c["off"],
             c["red"], total_spoofed, c["off"],
             c["yel"], total_unver, c["off"]))
    print("-" * 66)

    any_bot = False
    for name, g in groups.items():
        nv, ns, nu = len(g["verified"]), len(g["spoofed"]), len(g["unverifiable"])
        if nv == ns == nu == 0:
            continue
        any_bot = True
        src = "/".join(g["sources"]) if g["sources"] else ("%s段取不到%s" % (c["yel"], c["off"]))
        print("\n%s%-16s%s %s(%s)%s  %sverified=%d%s %sspoofed=%d%s %sunverifiable=%d%s  %s源:%s%s"
              % (c["bold"], name, c["off"], c["dim"], g["vendor"], c["off"],
                 c["grn"], nv, c["off"], c["red"], ns, c["off"], c["yel"], nu, c["off"],
                 c["dim"], src, c["off"]))
        # 冒充的逐条列出（最危险，优先看）
        for e in g["spoofed"][:8]:
            rd = ""
            if "rdns_ok" in e:
                rd = "  %srdns=%s%s" % (c["dim"], "ok" if e["rdns_ok"] else "no", c["off"])
            print("    %s[冒充]%s %-15s  %s\"%s\"%s%s"
                  % (c["red"], c["off"], e["ip"],
                     c["dim"], _trim(e["request"], 38), c["off"], rd))
        if ns > 8:
            print("    %s… 另有 %d 条冒充%s" % (c["dim"], ns - 8, c["off"]))
        # unverifiable 给个样例，提示去修缓存
        for e in g["unverifiable"][:2]:
            print("    %s[无法核验]%s %-15s  %s\"%s\"%s"
                  % (c["yel"], c["off"], e["ip"],
                     c["dim"], _trim(e["request"], 38), c["off"]))
        if nu > 2:
            print("    %s… 另有 %d 条无法核验（官方 IP 段未取到）%s" % (c["dim"], nu - 2, c["off"]))

    if not any_bot:
        print("本日志无自称 AI 爬虫的请求。")
    print("-" * 66)
    if total_spoofed:
        print("%s⚑ 发现 %d 条冒充 AI 爬虫的请求 —— 建议结合防火墙/速率限制处置。%s"
              % (c["red"], total_spoofed, c["off"]))


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


def maybe_alert(groups, cfg, state):
    tg = cfg["telegram"]
    if not tg.get("token") or not tg.get("chat_id"):
        print("⚠ 未配置 Telegram（SIEVE_TG_TOKEN / SIEVE_TG_CHAT 或 config.json），跳过告警。")
        return
    now = int(time.time())
    cooldown = cfg["alert_cooldown_minutes"] * 60
    thr = cfg["spoof_alert_threshold"]
    last = state.setdefault("last_alert", {})
    sent = 0
    for name, g in groups.items():
        spoofed = g["spoofed"]
        if len(spoofed) < thr:
            continue
        if now - int(last.get(name, 0)) < cooldown:
            continue
        lines = ["🕷️ <b>Sieve S1 告警 · 冒充 AI 爬虫</b>",
                 "自称 <code>%s</code>（%s）共 <b>%d</b> 条来源 IP 不在官方段内"
                 % (name, g["vendor"], len(spoofed)), ""]
        for e in spoofed[:6]:
            lines.append("• <code>%s</code> %s" % (e["ip"], _trim(e["request"], 40)))
        if len(spoofed) > 6:
            lines.append("…另有 %d 条" % (len(spoofed) - 6))
        try:
            if send_telegram(tg["token"], tg["chat_id"], "\n".join(lines)):
                last[name] = now
                sent += 1
        except Exception as e:  # noqa: BLE001 — 告警失败不应中断巡检
            print("Telegram 发送失败 (%s): %s" % (name, e))
    print("已推送 %d 条告警。" % sent)


# ── demo 数据 ──────────────────────────────────────────────

# demo 用文档保留地址段（RFC 5737），注入到内存里当"官方段"，不触网、不写缓存。
DEMO_RANGES = {
    "GPTBot": ["203.0.113.0/24"],          # TEST-NET-3
    "PerplexityBot": ["192.0.2.0/24"],     # TEST-NET-1
    # 故意不给 Anthropic 注入 → 演示 unverifiable 降级
}

DEMO_LOG = [
    # 普通浏览器流量：不自称爬虫，应被忽略
    '192.168.0.9 - - [19/Oct/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 5312 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36"',
    '198.18.0.44 - - [19/Oct/2026:08:00:05 +0000] "GET /blog/post-1 HTTP/1.1" 200 8231 "-" "Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/129.0"',
    # 真 GPTBot：IP 在官方段内 → verified
    '203.0.113.42 - - [19/Oct/2026:08:01:10 +0000] "GET /robots.txt HTTP/1.1" 200 210 "-" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"',
    '203.0.113.88 - - [19/Oct/2026:08:01:12 +0000] "GET /sitemap.xml HTTP/1.1" 200 1500 "-" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"',
    # 冒充 GPTBot：UA 写着 GPTBot，但 IP 不在官方段 → spoofed
    '45.137.21.9 - - [19/Oct/2026:08:02:00 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"',
    '45.137.21.9 - - [19/Oct/2026:08:02:03 +0000] "POST /xmlrpc.php HTTP/1.1" 403 0 "-" "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"',
    # 真 PerplexityBot → verified
    '192.0.2.77 - - [19/Oct/2026:08:03:00 +0000] "GET /feed.xml HTTP/1.1" 200 4096 "-" "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://www.perplexity.ai/perplexitybot)"',
    # 冒充 PerplexityBot → spoofed
    '103.224.182.251 - - [19/Oct/2026:08:03:30 +0000] "GET /.env HTTP/1.1" 404 0 "-" "PerplexityBot/1.0 (+https://www.perplexity.ai/perplexitybot)"',
    # 自称 ClaudeBot：demo 未注入 Anthropic 段 → unverifiable（演示降级）
    '185.220.101.5 - - [19/Oct/2026:08:04:00 +0000] "GET /docs/ HTTP/1.1" 200 9001 "-" "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"',
]


def demo_inject_ranges(bots):
    """用 DEMO_RANGES 构造内存 ranges，不触网、不读写缓存。"""
    ranges = {}
    for bot in bots:
        cidrs = DEMO_RANGES.get(bot["name"])
        if cidrs:
            ranges[bot["name"]] = {
                "nets": [ipaddress.ip_network(c) for c in cidrs],
                "ok": True, "sources": ["demo"],
            }
        else:
            ranges[bot["name"]] = {"nets": [], "ok": False, "sources": []}
    return ranges


# ── 主流程 ─────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Sieve S1 — 爬虫真伪核验（厂商官方 IP 段）")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--observe", action="store_true", help="只打印不告警（默认）")
    mode.add_argument("--alert", action="store_true", help="冒充超阈值推 Telegram")
    ap.add_argument("--demo", action="store_true", help="用合成日志演示，无需真实日志，不触网")
    ap.add_argument("--log", default=None, help="访问日志路径（combined/common 格式，覆盖配置）")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="配置文件路径")
    ap.add_argument("--rdns", action="store_true", help="附带 forward-confirmed rDNS 增强核验")
    ap.add_argument("--refresh-cache", action="store_true", help="忽略本地缓存，强制重新拉取 IP 段")
    ap.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    args = ap.parse_args()

    cfg = load_config(args.config)
    use_color = (not args.no_color) and sys.stdout.isatty()
    use_rdns = args.rdns or cfg.get("enable_rdns", False)

    if args.demo:
        records = [r for r in (parse_log_line(l) for l in DEMO_LOG) if r]
        print("（demo 模式：合成访问日志 %d 行，内存注入官方段，不触网）" % len(records))
        ranges = demo_inject_ranges(cfg["bots"])
        use_rdns = False  # demo 不做真实 DNS 查询
    else:
        log_path = args.log or cfg["log_path"]
        records = read_access_log(log_path)
        print("（读取日志 %s，解析出带 UA 的请求 %d 条）" % (log_path, len(records)))
        ranges = load_bot_ranges(cfg["bots"], cfg, use_cache=True, refresh=args.refresh_cache)

    groups, claimed = verify_records(records, cfg["bots"], ranges, cfg, use_rdns=use_rdns)
    print_report(groups, claimed, len(records), use_color)

    if args.alert:
        state = load_state()
        maybe_alert(groups, cfg, state)
        save_state(state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
