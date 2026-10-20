# Sieve S3 — Merge layer: S0(DNS) + S2(TLS) unified verdict

[简体中文](README.md) · **English**

> Merges the DNS-side (S0) and TLS-side (S2) signals per device and applies the verdict rules
> measured by `../sieve-verify/` to produce a unified alert. **Imports the real S0/S2 scoring code
> directly** — single source of truth; the merge layer only judges, it doesn't recompute.

This completes the product nucleus: collect (Pi-hole + Zeek) → two-layer scoring → merged verdict → alert.

---

## Verdict rules (not a sum of two scores)

Verification proved that "summing the two scores" mis-flags humans using ChatGPT. S3 instead uses:

| Rule | Why |
|---|---|
| **S2 as primary judge**: JA4 = script (+40) → alert | TLS layer has the highest precision |
| **S0 for recall**: catches cases with no TLS record | Neither layer is dispensable |
| Alert only on **≥2 independent signal families OR a script confirmation** | Don't let a single S0 signal fire alone |
| **Human guardrail**: if the only evidence is "connected to an AI domain" and TLS says browser → downgrade to "watch" | Blocks the ChatGPT false positive |
| **Both layers hit = high confidence** | Matches "same device on both sides" |

**Independent signal families**: fold same-source evidence together to avoid double-counting.
`llm` (LLM API / agent / first-seen sensitive domain) · `script` (non-browser JA4) · `beacon`
(regular reconnect) · `egress` (large egress) · `fanout` · `doh` (DoH bypass).
"Hit openai.com + first-seen" counts as **1 family**, not 2 — which is exactly what blocks the
ChatGPT false positive.

Verdict levels: **alert** (pushed) · **watch** (logged, not pushed) · **ok** · **exempt** (allowlist).

---

## 30-second demo (runs on a Mac)

```bash
python3 sieve_s3.py --demo
```

Merges S0 and S2 synthetic data, output like:

```
192.168.1.99  alert conf=high  (DNS 75/TLS 95)  [DNS][TLS] ⚑both hit   LLM+beacon+script JA4
192.168.1.33  alert conf=med   (DNS  0/TLS 60)  [TLS]                  script JA4 + large egress
192.168.1.50  exempt                                                   allowlisted dev box
```

Measured on the golden set: **FP=0, FN=0** (see `../sieve-verify/`).

---

## Real deployment

Prereq: both S0 (Pi-hole) and S2 (Zeek) are running per their own READMEs.

```bash
cp config.example.json config.json
# edit: pihole_db, zeek_logs_dir, known_ai_clients
python3 sieve_s3.py --observe                 # look first
export SIEVE_TG_TOKEN=... SIEVE_TG_CHAT=...
python3 sieve_s3.py --alert                   # push alert-level devices to Telegram
```

Schedule like S0/S2 (cron / systemd timer), command `sieve_s3.py --alert`.
Once S3 runs, **you don't need to alert from S0/S2 separately** — it merges both; keep S0/S2 on
`--observe` for triage.

---

## Config notes (from the verification conclusions — don't casually revert)

| Key | Default | Meaning |
|---|---|---|
| `union_threshold` | 55 | Union (max of both layers) alert threshold |
| `s2_automated_min` | 40 | Minimum score for an S2 script confirmation (i.e. JA4=script itself) |
| `known_ai_clients` | — | Expected-LLM devices, shared by both layers, uniformly exempt |
| `alert_cooldown_minutes` | 180 | Per-device alert deduplication |

---

## Files

| File | Purpose |
|---|---|
| `sieve_s3.py` | Merge-verdict engine (imports S0/S2, emits unified alerts) |
| `config.example.json` | Config template |
| `sieve_s3_state.json` | Auto-generated: alert cooldown |

---

## The full pipeline

```
collect       score              merge           alert
Pi-hole  ─▶  S0 (DNS signals) ┐
                              ├─▶  S3 verdict ─▶  Telegram
Zeek+JA4 ─▶  S2 (TLS signals) ┘
                   ▲
          sieve-verify continuously re-tests with real data, feeds tuning back
```

After going live, re-test periodically with `../sieve-verify/evaluate.py --from-live` and re-tune
as your network changes.

---

*Use only on networks you own or are authorized to test.*
