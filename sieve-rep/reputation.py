#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve Reputation — 跨租户信誉库引擎（护城河）
===============================================

核心思想：单个 Sieve 装机点看到的是局部；把各装机点**本地判为可疑的公共指标**
（公共 LLM/爬虫域名、JA4 指纹）按**跨租户去重计数**汇总成一份信誉源，每个装机点
再消费它，就能"一处标坏、处处预警"。越多人用越准——这是网络效应护城河。

本文件是纯引擎（被 contribute.py / aggregate.py / sieve-s3 复用），不做 IO 以外的副作用。
纯标准库。

隐私与抗投毒原则（详见 README）：
  · 只收录"可疑指标"本身（域名/JA4），不含 IP、设备、时间点、浏览历史、正常流量。
  · 信誉强度 = 举报的**不同租户数**（每租户对同一指标只计一次），单个投毒者无法刷高。
  · 信誉源带内容哈希校验；生产环境应再加 GPG 签名（见 README）。
"""

import hashlib
import json
import os
import time

SCHEMA_VERSION = 1

# 可贡献的类别——只有这些"公共指标"才允许进信誉库；
# 任何不在此列的（尤其是内网域名）一律不收录，由 contribute.py 过滤。
CONTRIBUTABLE_CATEGORIES = {
    "llm_api", "agent_infra", "content_farm", "scraper", "doh_resolver", "ja4_script",
}


# ── 指标 key ────────────────────────────────────────────────

def make_key(kind, value):
    """kind ∈ domain|ja4。域名统一小写去尾点；ja4 取下划线前的 JA4_a 做稳定键。"""
    v = (value or "").strip().lower()
    if kind == "domain":
        v = v.rstrip(".")
    elif kind == "ja4":
        v = v.split("_")[0]  # JA4_a 结构部分，版本细节变化不影响归并
    return "%s:%s" % (kind, v)


def split_key(key):
    kind, _, value = key.partition(":")
    return kind, value


# ── 信誉源 读 / 写 / 校验 ──────────────────────────────────

def _entries_hash(entries):
    """对 entries 做规范化 JSON 的 sha256，用于完整性校验。"""
    blob = json.dumps(entries, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def new_feed():
    return {"schema": SCHEMA_VERSION, "version": 0, "generated": "",
            "entries": {}, "integrity": _entries_hash({})}


def load_feed(path):
    """读信誉源；不存在返回空源。校验完整性，被篡改则打印警告但仍返回（调用方自行决定信任）。"""
    if not path or not os.path.exists(path):
        return new_feed()
    try:
        with open(path, encoding="utf-8") as f:
            feed = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print("⚠ 信誉源读取失败（忽略，按空源处理）: %s" % e)
        return new_feed()
    entries = feed.get("entries", {})
    want = feed.get("integrity")
    got = _entries_hash(entries)
    if want and want != got:
        print("⚠ 信誉源完整性校验失败——内容可能被篡改，请核对来源。")
        feed["_integrity_ok"] = False
    else:
        feed["_integrity_ok"] = True
    return feed


def save_feed(path, feed):
    feed = dict(feed)
    feed["schema"] = SCHEMA_VERSION
    feed["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    feed["integrity"] = _entries_hash(feed.get("entries", {}))
    feed.pop("_integrity_ok", None)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(feed, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return feed


# ── 查询 ───────────────────────────────────────────────────

def lookup_domain(feed, domain):
    """域名后缀匹配（带点边界），返回 entry 或 None。"""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return None
    entries = feed.get("entries", {})
    exact = entries.get("domain:" + d)
    if exact:
        return exact
    # 后缀：api.openai.com 命中收录的 openai.com；取最长后缀命中
    best, best_suffix = None, ""
    for key, ent in entries.items():
        if not key.startswith("domain:"):
            continue
        suffix = key[len("domain:"):]
        if d == suffix or d.endswith("." + suffix):
            if len(suffix) > len(best_suffix):
                best, best_suffix = ent, suffix
    return best


def lookup_ja4(feed, ja4):
    return feed.get("entries", {}).get(make_key("ja4", ja4))


def reputation_signal(feed, domains, ja4s, confirm_min_tenants):
    """
    给一台设备看到的 domains / ja4s，查信誉库。
    返回 (命中列表)，每项 = (kind, value, entry)；只返回达到跨租户确认阈值的"坏"指标。
    这是 sieve-s3 要消费的函数——纯附加信号，拿不到源就返回空，绝不改变原有判定。
    """
    hits = []
    seen = set()
    for d in domains or []:
        ent = lookup_domain(feed, d)
        if ent and ent.get("verdict") == "bad" and ent.get("tenants", 0) >= confirm_min_tenants:
            k = ("domain", ent["indicator"])
            if k not in seen:
                seen.add(k); hits.append(("domain", d, ent))
    for j in ja4s or []:
        ent = lookup_ja4(feed, j)
        if ent and ent.get("verdict") == "bad" and ent.get("tenants", 0) >= confirm_min_tenants:
            k = ("ja4", ent["indicator"])
            if k not in seen:
                seen.add(k); hits.append(("ja4", j, ent))
    return hits


# ── 聚合：把多份 sighting report 并成信誉源 ────────────────

def merge_reports(reports, confirm_min_tenants=3, max_per_tenant=500):
    """
    reports: [{"tenant_id": "...", "month": "YYYY-MM", "sightings": [{kind,value,category}, ...]}, ...]
    跨租户去重计数：同一指标，同一 tenant_id 只计一次。
    verdict：确认阈值内的租户数 >= confirm_min_tenants → bad，否则 suspicious。
    max_per_tenant：单租户单次最多计入的指标数，抑制投毒刷量。
    """
    acc = {}  # key -> {kind, value, category_votes{}, tenants:set, sightings, first, last}
    for rep in reports:
        tid = rep.get("tenant_id") or "anon"
        month = rep.get("month") or ""
        sightings = rep.get("sightings", [])[:max_per_tenant]
        for s in sightings:
            kind, value, cat = s.get("kind"), s.get("value"), s.get("category")
            if kind not in ("domain", "ja4") or not value:
                continue
            if cat not in CONTRIBUTABLE_CATEGORIES:
                continue  # 二次防线：聚合端也拒收非公共类别
            key = make_key(kind, value)
            a = acc.setdefault(key, {"kind": kind, "value": split_key(key)[1],
                                     "cats": {}, "tenants": set(), "sightings": 0,
                                     "first": month, "last": month})
            a["tenants"].add(tid)
            a["sightings"] += 1
            a["cats"][cat] = a["cats"].get(cat, 0) + 1
            if month:
                a["first"] = min(a["first"] or month, month)
                a["last"] = max(a["last"] or month, month)

    entries = {}
    for key, a in acc.items():
        tenants = len(a["tenants"])
        category = max(a["cats"].items(), key=lambda kv: kv[1])[0] if a["cats"] else "unknown"
        entries[key] = {
            "indicator": a["value"],
            "kind": a["kind"],
            "category": category,
            "verdict": "bad" if tenants >= confirm_min_tenants else "suspicious",
            "tenants": tenants,
            "sightings": a["sightings"],
            "first_seen": a["first"],
            "last_seen": a["last"],
        }
    feed = new_feed()
    feed["entries"] = entries
    feed["confirm_min_tenants"] = confirm_min_tenants
    return feed
