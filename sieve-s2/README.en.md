# Sieve S2 — TLS-fingerprint detector (Zeek + JA4)

[简体中文](README.md) · **English**

> Stage 2 prototype. On top of S0 (DNS-only), it adds three things S0 can't see:
> **① judge whether a client is a script via JA4 fingerprint** (python/curl/go ≠ a real browser);
> **② beaconing cadence from real connections**; **③ egress volume**.
>
> **Pure Python standard-library analyzer** (no `pip install`); the collection side needs a machine
> running Zeek + a traffic-mirror source.

Companion: `../sieve-s0/` (DNS layer, reuses its `domains.txt`); parent `docs/agent-trace-playbook.html`.

---

## Which S0 blind spot S2 covers

| | S0 (DNS) | S2 (TLS fingerprint) |
|---|---|---|
| Client is a script? | ✗ | ✅ JA4 fingerprint |
| Beaconing | rough guess via DNS | ✅ real connections + bytes |
| Egress volume / exfil | ✗ | ✅ orig_bytes |
| When bypassed via DoH | fully blind | ✅ still visible at IP layer |

**Honest limit**: JA4 catches lazy scripts (requests / urllib / curl / scanners), not an adversary
deliberately forging a browser fingerprint with `curl_cffi --impersonate chrome` / `tls-client` —
those land as `unknown` or `browser`. So JA4 is **one signal**; high confidence comes from stacking
it with "hit an LLM domain + regular beaconing". That's why this is scoring, not a single rule.

---

## 30-second demo (no Zeek, runs on a Mac)

```bash
python3 sieve_s2.py --demo
```

Synthetic ssl/conn logs, output like:

```
192.168.1.99  score=95 [review]  +40 non-browser JA4  +30 LLM API  +25 beacon
192.168.1.23  score=70 [alert]   +40 non-browser JA4 (python→api.openai.com)
192.168.1.33  score=60 [alert]   +40 non-browser JA4 (by-IP)  +20 large egress 90MB
192.168.1.50  score= 0 [allowlist] browser JA4, expected-LLM, exempt
```

(A normal browser device, 192.168.1.11, scores 0 and doesn't appear in the report.)

---

## Real deployment

### 1. Get a traffic mirror
Feed the traffic to monitor to Zeek's NIC, one of three ways:
- **Managed-switch SPAN / mirror port** (recommended): mirror the uplink to the Zeek machine's port.
- **Software router**: port mirroring on OpenWRT/pfSense, or run Zeek on the gateway directly.
- **Optical TAP**: cleanest, but needs hardware.

### 2. Install Zeek + the JA4 package
```bash
# Debian / Raspberry Pi example
sudo apt install zeek zkg            # or from zeek.org
sudo zkg install zeek/ja4            # official JA4 package, adds the ja4 field to ssl.log
```

### 3. Start Zeek (JSON logs + JA4)
```bash
sudo zeek -i eth0 -C /opt/sieve-s2/zeek/sieve-ja4.zeek
# logs go to the current dir; for production use zeekctl, logs in /opt/zeek/logs/current
```

### 4. Run the analyzer
```bash
cp config.example.json config.json
# edit config.json: zeek_logs_dir, local_nets (your LAN ranges), known_ai_clients
python3 sieve_s2.py --observe --logs /opt/zeek/logs/current
```

First two weeks `--observe`: meanwhile confirm recurring JA4s against devices and add them to
`ja4_fingerprints.txt` (below), then enable `--alert`.

---

## How JA4 classification works

Priority: **exact match in the table → prefix match → structural heuristic**.

The heuristic parses JA4_a (the part before the first underscore, e.g. `t13d1516h2`): TLS version,
SNI presence, cipher count, extension count, ALPN. Scoring markers:

| Marker | Meaning |
|---|---|
| No ALPN (`00`) | Browsers always send ALPN; absence is a strong script signal (+2) |
| HTTP/1.1 only (`h1`) | Modern browsers negotiate h2 (+1) |
| Very few extensions (≤8 / ≤11) | Raw-library fingerprint (+2 / +1) |
| No SNI (connect by IP, `i`) | Scanning / automation (+1) |
| TLS ≤ 1.2 only | Old client / library (+1) |

≥3 → `automated` (likely script); =2 → leaning automated; many extensions + h2 and no markers →
`browser`; otherwise → `unknown` (leave it blank rather than mislabel a browser).

**Baselining**: put full JA4s you've confirmed on your own network into `ja4_fingerprints.txt`
(e.g. "this one is Chrome"); exact matches override the heuristic and false positives drop. Don't
blindly copy hardcoded external fingerprints — they change the moment a client updates.

---

## Scoring (tunable in config.json)

| Signal | Points | Source |
|---|---|---|
| `non_browser_ja4` | +40 | ssl.log · JA4 judged automated |
| `llm_api` | +30 | ssl.log · SNI hit an LLM domain |
| `agent_infra` | +20 | ssl.log · SNI hit agent infrastructure |
| `beaconing` | +25 | conn.log · regular-interval reconnect to one external IP (CV≤0.35) |
| `large_egress` | +20 | conn.log · single connection egress ≥ 50MB |
| `fanout_burst` | +20 | conn.log · external hosts ≥ 40 |
| `doh_resolver` | +15 | ssl.log · SNI hit a DoH resolver |

Allowlisted devices (`known_ai_clients`) are exempt from JA4 / LLM / agent points, but beacon,
egress, and DoH still count. Default **≥50 alert · ≥80 review**.

---

## Scheduling

Same as S0 (cron / systemd timer), swap the command for `sieve_s2.py --alert`. Match the period
to `window_minutes`.

---

## Files

| File | Purpose |
|---|---|
| `sieve_s2.py` | Analyzer |
| `zeek/sieve-ja4.zeek` | Zeek site config (JSON + load JA4 package) |
| `ja4_fingerprints.txt` | JA4 annotation table (build from your own baseline) |
| `config.example.json` | Config template |
| `sieve_s2_state.json` | Auto-generated: alert cooldown |

---

## Reading S0 + S2 together

Both score per device and push Telegram. S0 from the DNS side, S2 from the TLS/connection side —
**the same device surfacing on both = high confidence**. The next step (S3) merges the two per
device into one alert.

The most valuable thing to do now: run the **T1–T7** self-tests from the playbook on your own
network, see these two scripts' false positives / negatives, and tune `weights` and thresholds.

---

*Use only on networks you own or are authorized to test.*
