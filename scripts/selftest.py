#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve 回归自测：用 golden 标注集跑真实的 S0+S2+S3 研判，断言 FP=0 且 FN=0。
CI 和改动打分逻辑后都应跑这个。退出码非 0 表示回归。
"""
import importlib.util, json, os, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
G = os.path.join(ROOT, "sieve-verify", "golden")


def load(name, rel):
    path = os.path.join(ROOT, rel)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def jl(f):
    with open(os.path.join(G, f), encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def main():
    s0 = load("sieve_s0", "sieve-s0/sieve_s0.py")
    s2 = load("sieve_s2", "sieve-s2/sieve_s2.py")
    s3 = load("sieve_s3", "sieve-s3/sieve_s3.py")

    now = int(time.time())
    labels = json.load(open(os.path.join(G, "labels.json"), encoding="utf-8"))
    dns, ssl, conn = jl("dns.jsonl"), jl("ssl.jsonl"), jl("conn.jsonl")

    s0_rows = [(now - r["t_offset"], r["client"], r["domain"]) for r in dns]
    ssl_rows = [{"id.orig_h": r["client"], "id.resp_h": r["resp"],
                 "server_name": r["sni"], "ja4": r["ja4"], "ts": now - r["t_offset"]} for r in ssl]
    conn_rows = [{"id.orig_h": r["client"], "id.resp_h": r["resp"],
                  "orig_bytes": r["orig_bytes"], "resp_bytes": r["resp_bytes"],
                  "ts": now - r["t_offset"]} for r in conn]

    cfg = s3.load_config(None)
    known = [c for c, m in labels.items() if m.get("known")] or ["10.0.0.50"]
    cfg["known_ai_clients"] = known
    cfg0 = s0.load_config(None); cfg0["known_ai_clients"] = known
    cfg2 = s2.load_config(None); cfg2["known_ai_clients"] = known
    dmap = s0.load_domains(os.path.join(ROOT, "sieve-s0", "domains.txt"))
    fps = s2.load_fingerprints(cfg2["fingerprints_file"])

    r0 = s0.score_clients(s0_rows, cfg0, dmap, baseline={})
    r2 = s2.score(ssl_rows, conn_rows, cfg2, dmap, fps)
    merged = s3.merge(r0, r2, cfg)

    fp = fn = 0
    for d in merged:
        truth = labels[d["client"]]["truth"]
        alerted = d["level"] == "告警"
        if truth == "benign" and alerted:
            fp += 1; print("FP:", d["client"], labels[d["client"]]["scenario"])
        if truth == "malicious" and not alerted:
            fn += 1; print("FN:", d["client"], labels[d["client"]]["scenario"])

    print("selftest: FP=%d FN=%d  (设备=%d)" % (fp, fn, len(labels)))
    if fp or fn:
        print("❌ 回归：合并研判在 golden 集上不再是 FP=0 FN=0")
        return 1
    print("✅ 通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
