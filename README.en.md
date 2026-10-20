<div align="center">

# 🧭 Sieve

**Detect anomalous AI & agent traffic on your home or office network**

Shadow-AI exfiltration · scripted scraping · autonomous-agent beaconing · DoH bypass

[![license: MIT](https://img.shields.io/badge/license-MIT-0d7268)](LICENSE)
[![python](https://img.shields.io/badge/python-3.8%2B-0d7268)](#dependencies)
[![deps: stdlib only](https://img.shields.io/badge/deps-stdlib%20only-0d7268)](#dependencies)
[![status: prototype](https://img.shields.io/badge/status-prototype-eda100)](#roadmap)

[简体中文](README.md) · **English**

</div>

---

Sieve detects **anomalous AI / agent behavior** from the network side — not *what* was read
(no MITM at the router means content stays invisible), but *who is using AI, is it a human or
a script, and should it alert*. Two vantage points (DNS + TLS fingerprint) score independently,
then merge into one verdict and one alert.

> **Scope**: anomaly detection, not content inspection.
> **Boundary**: use only on networks you own or are authorized to test.

```
collect             score                   merge          alert
┌─────────┐   ┌──────────────────┐
│ Pi-hole │──▶│ S0  DNS signals   │─┐
└─────────┘   └──────────────────┘  │   ┌──────────┐    ┌──────────┐
                                     ├──▶│ S3 verdict│───▶│ Telegram │
┌─────────┐   ┌──────────────────┐  │   └──────────┘    └──────────┘
│Zeek+JA4 │──▶│ S2  TLS signals   │─┘        ▲
└─────────┘   └──────────────────┘           │
                     sieve-verify re-tests with real data and feeds tuning back
```

> **Two complementary lines**: S0 + S2 → S3 above is the **outbound line** — it catches internal agents / devices reaching out (DNS + outbound TLS, threat models B/C).
> A parallel **inbound line**, [`sieve-s1/`](sieve-s1/), checks your public-facing services' access logs: it verifies whether requests that claim to be AI crawlers (UA containing GPTBot / ClaudeBot / PerplexityBot, etc.) really belong to the vendor (threat model A).
> The two lines differ in data source and direction — complementary, and S1 does not feed into S3.

## ⚡ 60-second start (no infrastructure needed)

```bash
git clone https://github.com/Qiaofei-Y/agent-sieve.git && cd agent-sieve
python3 sieve-s0/sieve_s0.py --demo       # DNS layer
python3 sieve-s2/sieve_s2.py --demo       # TLS fingerprint layer
python3 sieve-verify/evaluate.py          # accuracy eval (with false-positive traps)
python3 sieve-s3/sieve_s3.py --demo       # merged verdict
# or:
make demo
```

Pure Python standard library — **no `pip install`**.

## 🧩 Components

| Directory | What it is | Status |
|---|---|---|
| [`sieve-s0/`](sieve-s0/) | **S0** · Pi-hole DNS-layer detector | ✅ |
| [`sieve-s1/`](sieve-s1/) | **S1** · crawler authenticity verification (inbound access logs × vendors' official IP ranges) | ✅ |
| [`sieve-s2/`](sieve-s2/) | **S2** · Zeek + JA4 TLS-fingerprint detector | ✅ |
| [`sieve-s3/`](sieve-s3/) | **S3** · merged verdict, unified alerting | ✅ |
| [`sieve-verify/`](sieve-verify/) | Accuracy eval + tuning (runs the real S0/S2 code) | ✅ |
| [`docs/`](docs/) | Purple-team playbook, validation runbook, console design (HTML) | — |

Every component runs standalone — you don't have to build the whole stack first.
Each directory has its own README (Chinese).

## 🧠 Design conclusions (all measured by [`sieve-verify`](sieve-verify/))

1. **DNS alone wrongs people**: a developer using ChatGPT in a browser gets mis-flagged by the
   DNS layer (F1 0.75).
2. **TLS fingerprinting fixes it**: JA4 tells scripts from browsers apart; S2 hits 100% precision.
3. **Neither layer is dispensable**: a pure DoH bypass has no LLM domain — only S2's script
   fingerprint catches it.
4. **Merging ≠ summing**: S3 uses "S2 as primary judge + ≥2 independent signal families +
   human guardrail", scoring **FP=0 FN=0** on the golden set.

Honest limits: tools like `curl_cffi` can forge a browser JA4 (so JA4 catches lazy scripts, not
determined ones); DoH/ECH keep narrowing visibility, so block DoH at the firewall. See the
[playbook](docs/agent-trace-playbook.html).

## 🚀 Real deployment

1. Point router DHCP's DNS at Pi-hole → run `sieve-s0 --observe` for **two weeks** to build a baseline.
2. Mirror a switch SPAN port to a Raspberry Pi running Zeek (`zkg install zeek/ja4`) → `sieve-s2 --observe`.
3. Run the T1–T7 self-tests from the [validation runbook](docs/validation-runbook.html); measure
   false positives / negatives and tune with `sieve-verify`.
4. Once both layers are in place, `sieve-s3 --alert` for unified alerting.

> 📋 Full validation flow: the interactive **[validation runbook](docs/validation-runbook.html)**
> (checklist + live precision/recall calculator).

## 📎 Dependencies

- Python 3.8+ (standard library, no third-party packages)
- Runtime: [Pi-hole](https://pi-hole.net/) (S0); [Zeek](https://zeek.org/) +
  [`zeek/ja4`](https://github.com/FoxIO-LLC/ja4) (S2)
- Alerts: Telegram Bot (optional)

## 🗺 Roadmap

- [x] S0 DNS layer · S2 TLS layer · S3 merge · verification framework
- [ ] Real-network validation, produce measured precision
- [x] S1 crawler authenticity verification (vendor IP JSON)
- [ ] Cross-tenant domain-reputation / JA4-fingerprint DB (the moat)
- [ ] Hosted version / web console

## 🤝 Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
Most valuable contributions: add LLM/agent domains to [`domains.txt`](sieve-s0/domains.txt),
and JA4 fingerprints you've confirmed on your own network.

## 📄 License

[MIT](LICENSE) · Use only on networks you own or are authorized to test.
