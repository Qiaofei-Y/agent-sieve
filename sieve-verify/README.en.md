# Sieve Verify — detection accuracy validation + tuning

[简体中文](README.md) · **English**

> Before merging S0/S2, **measure** them with ground-truth data: how accurate, where the false
> positives are, what the threshold should be. It runs the **real S0/S2 scoring code** (imported
> directly), not a rewrite.

Companion: `../sieve-s0/` (DNS layer), `../sieve-s2/` (TLS layer), parent
`docs/agent-trace-playbook.html` (source of T1–T7).

---

## Why validate first

In the demos both detectors catch obvious bad traffic — but "catches the bad" ≠ "doesn't wrong the
good". What actually decides whether the product survives is **false positives**: treat a developer
normally using ChatGPT as an attack and users uninstall within three days. This stage quantifies that
with "false-positive traps".

---

## 30-second conclusion (runs on a Mac)

```bash
python3 evaluate.py
```

Runs the real S0/S2 over the built-in labeled set (4 malicious scenarios + 6 benign traps):

| Layer | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| **S0 (DNS only)** | 75% | 75% | 0.75 | 1 | 1 |
| **S2 (TLS fingerprint)** | 100% | 100% | **1.00** | 0 | 0 |
| **Union S0∪S2** | 80% | 100% | 0.89 | 1 | 0 |

### The real conclusions from this data

1. **S0 wrongs people.** A developer using ChatGPT in a browser (B1) gets hit for 50 by the DNS
   layer → false positive. DNS only sees "connected to openai.com" and can't tell a human clicking
   from a script scraping.
2. **S2 fixes it.** Same device, JA4 fingerprint is a browser → no +40 → 30 points → correctly
   passed; only a script connecting directly to the LLM gets the +40. **This is the reason S2 was
   built, now quantified.**
3. **Neither layer is dispensable.** A pure DoH bypass (T4) has no LLM domain, so S0 scores only 15
   and misses it; S2 catches it via "by-IP script JA4 +40".
4. **Be careful merging**: at threshold 50 the union inherits S0's false positive on B1 (takes the
   max); the threshold sweep shows **raising the union threshold to 55, or not letting S0 fire alone
   → F1 back to 1.00.** — exactly the rule S3 should adopt, rather than blindly summing.

> In other words: **S3 merge ≠ sum of two scores. Use S2 as primary judge, S0 for recall, and
> require "≥2 signals or an S2 hit" to alert.** This came out of validation, not a guess.

---

## Two data sources

### A. Built-in labeled set (validates the method + runs on a Mac)
Three JSON-lines files + `labels.json` under `golden/`, with relative timestamps (rebased to now at
runtime), deliberately including false-positive traps:

| Device | Label | Trap / scenario |
|---|---|---|
| 10.0.0.11 | benign | **ChatGPT in a browser** (DNS layer mis-flags) |
| 10.0.0.12 | benign | Backup client regular heartbeat (beaconing trap) |
| 10.0.0.13 | benign | CDN-heavy site (fanout trap) |
| 10.0.0.14 | benign | Cloud-drive large upload (large_egress trap) |
| 10.0.0.50 | benign | Allowlisted dev box (tests known_ai_clients) |
| 10.0.0.23/77/88/99 | malicious | T1 exfil / T5 agent / T4 DoH / T6 beacon |

Edit these files to add scenarios you care about.

### B. Real-network data (tune your own parameters)
```bash
# 1) Run T1–T7 with real traffic on a LAN machine (below) to get attack_manifest.jsonl
# 2) Turn the manifest into labels.json (client → {truth, scenario})
# 3) Re-run the eval over the real Pi-hole DB + Zeek logs:
python3 evaluate.py --from-live \
    --pihole-db /etc/pihole/pihole-FTL.db \
    --zeek-logs /opt/zeek/logs/current \
    --labels labels.json --window 60
```
Then change each module's `config.json` `weights` and thresholds based on the measured results.

---

## Real-network self-test: run_attacks.py

On **your own** network, emit labeled test traffic from the current machine so the in-network S0/S2
observe it.

```bash
python3 run_attacks.py --list
python3 run_attacks.py --test t1 --yes                      # shadow exfil: python direct to LLM API
python3 run_attacks.py --test t4 --yes                      # DoH bypass
python3 run_attacks.py --test t6 --target 192.168.1.9       # beacon: regular reconnect to your own host
python3 run_attacks.py --test t2 --target https://your-intranet-site/  # scripted scraping
python3 run_attacks.py --test b1 --yes                      # benign control
```

Each run appends a record to `attack_manifest.jsonl` (time window + label) to build your labels.

**Safety constraints**: only against targets you own/are authorized for; by default only TLS
handshakes or unauthenticated small requests, no real data sent; tests needing a target (t2/t6) must
explicitly `--target` your own host. T3/T5/T7 involve external tools or a real agent — run them
manually per the playbook.

> Note: even if a handshake fails due to the local cert store, the **TLS ClientHello (carrying the
> JA4 fingerprint + SNI) has already been sent** — the detector still observes it, so the test intent
> still holds.

---

## Files

| File | Purpose |
|---|---|
| `evaluate.py` | Evaluator: imports real S0/S2 → confusion matrix + P/R/F1 + FP attribution + threshold sweep + advice |
| `run_attacks.py` | Real-network self-test traffic generator (T1/T2/T4/T6/B1) |
| `golden/*.jsonl`, `golden/labels.json` | Built-in labeled set (with FP traps, editable) |
| `attack_manifest.jsonl` | Generated at run_attacks runtime |

---

## Next: S3 merge (now with evidence)

The merge rules validation produced:
- **S2 as primary judge** (100% precision), S0 for recall (catches cases with no TLS record).
- **Alert gate**: an S2 hit, or the same device with "≥2 independent signals" across S0+S2 — don't
  let a single S0 signal alert alone.
- Union threshold **55** per this evaluation.
- After going live, re-test periodically with `--from-live` and re-tune as your network changes.

---

*Use only on networks you own or are authorized to test.*
