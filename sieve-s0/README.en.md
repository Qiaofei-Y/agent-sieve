# Sieve S0 — Minimal home-network AI / Agent traffic detector

[简体中文](README.md) · **English**

> Stage 0 prototype. From Pi-hole's DNS query log, finds per-device traces of
> **LLM API / agent infrastructure / DoH bypass**, scores them, and pushes a Telegram
> alert above threshold.
>
> **Pure Python standard library, no `pip install`, runs out of the box on a Raspberry Pi.**

Companion docs in the parent `docs/`: `agent-trace-playbook.html` (purple-team playbook) and
`sieve-console.html` (console design).

---

## What it does / doesn't

| Does | Doesn't |
|---|---|
| Catch LAN devices hitting LLM APIs (shadow-AI exfiltration) | See encrypted content (no MITM root cert) |
| Catch local agents using system DNS | Catch clients that bypass your DNS via DoH/DoT |
| Catch devices trying to bypass your DNS (DoH resolvers) | Do "AI content review" — this is anomaly detection |

S0 uses **DNS as its only vantage point**. For script-client fingerprints (JA4) and connection
volume, see S2 (Zeek + mirror port) in the playbook.

---

## 30-second demo (no Pi-hole, runs on a Mac)

```bash
python3 sieve_s0.py --demo
```

Runs over synthetic data, output like:

```
192.168.1.77        score= 95  [review]       ← local agent: LLM calls + domain burst + regular beacon
192.168.1.23        score= 50  [alert]        ← shadow AI: a device that shouldn't touch LLM hitting api.openai.com
192.168.1.88        score= 15  [ok]           ← connected to a DoH resolver
192.168.1.50        score=  0  [ok][allowlist] ← expected-LLM device, exempted
```

---

## Real deployment (3 steps)

### 1. Make Pi-hole your network-wide DNS
In the router's DHCP settings, point the DNS handed to clients at Pi-hole's IP. Every device's
DNS queries then pass through Pi-hole and land in `pihole-FTL.db`.

### 2. Put this directory on the Pi-hole host
```bash
cp config.example.json config.json
# edit config.json: confirm pihole_db path, fill known_ai_clients (expected-LLM devices)
python3 sieve_s0.py --observe
```

> **For the first two weeks use `--observe` only** — no alerts. Let it fold each device's normal
> sensitive domains into the baseline (`sieve_state.json`), or week one drowns in normal traffic.

### 3. Enable alerts after the baseline is built
```bash
export SIEVE_TG_TOKEN="123456:ABC..."     # see Telegram setup below
export SIEVE_TG_CHAT="your chat id"
python3 sieve_s0.py --alert
```

---

## Scheduling

### cron (hourly)
```cron
0 * * * * SIEVE_TG_TOKEN=... SIEVE_TG_CHAT=... /usr/bin/python3 /opt/sieve-s0/sieve_s0.py --alert >> /var/log/sieve-s0.log 2>&1
```

### systemd timer
`/etc/systemd/system/sieve-s0.service`
```ini
[Service]
Type=oneshot
Environment=SIEVE_TG_TOKEN=123456:ABC...
Environment=SIEVE_TG_CHAT=yourchatid
ExecStart=/usr/bin/python3 /opt/sieve-s0/sieve_s0.py --alert
```
`/etc/systemd/system/sieve-s0.timer`
```ini
[Timer]
OnCalendar=hourly
Persistent=true
[Install]
WantedBy=timers.target
```
```bash
sudo systemctl enable --now sieve-s0.timer
```

> The schedule period (e.g. hourly) should match `window_minutes` to avoid gaps or double-counting.

---

## Telegram setup

1. Create a bot via **@BotFather**, get the token.
2. Send your bot a message, then open
   `https://api.telegram.org/bot<token>/getUpdates` and find `chat.id` in the response.
3. Put them in env vars `SIEVE_TG_TOKEN` / `SIEVE_TG_CHAT` (higher priority than config.json).

Works without it — `--alert` prints the alert content but skips the push.

---

## CLI

```
--demo                 synthetic-data demo, no Pi-hole needed
--observe              print only, no alerts (for baselining)
--alert                push Telegram above threshold
--window N             look back N minutes (overrides window_minutes)
--config PATH          config file (default ./config.json)
--no-color             disable colored output
--no-baseline-update   don't write baseline this run
```

---

## Scoring (tunable in config.json)

| Signal | Points | Meaning |
|---|---|---|
| `llm_api` | +30 | Hit an LLM API domain (exempt for allowlisted devices) |
| `agent_infra` | +20 | Hit agent/scraping infrastructure (exempt for allowlisted) |
| `beaconing` | +25 | A sensitive domain queried at regular intervals (CV ≤ 0.35) |
| `shadow_source` | +20 | A sensitive domain seen for the first time vs. baseline |
| `fanout_burst` | +20 | Distinct domains in the window ≥ 40 |
| `doh_resolver` | +15 | Connected to a known DoH resolver (DNS-bypass attempt) |

Scores accumulate per device within the time window. Default **≥ 50 alert · ≥ 80 review**.

Tuning: `weights`, `fanout_threshold`, `beaconing_min_hits`, `beaconing_max_cv`,
`alert_threshold`, `review_threshold`, `alert_cooldown_minutes`.

---

## Files

| File | Purpose |
|---|---|
| `sieve_s0.py` | Main program |
| `domains.txt` | LLM / agent / DoH domain list (edit & update periodically) |
| `config.example.json` | Config template, copy to `config.json` |
| `sieve_state.json` | Auto-generated: per-device baseline + alert cooldown |

---

## Next steps (per the playbook)

- **S1**: against exposed reverse-proxy/NAS logs, verify crawler authenticity using vendor IP JSON.
- **S2**: mirror port + Zeek for JA4 fingerprints — catch script clients and beaconing, the part
  S0 can't see.
- **Block DoH**: firewall port 853 and block the DoH resolvers in `domains.txt`, or the DNS layer
  can be bypassed at any time. Run test **T4** from the playbook first to see if you're currently blind.

---

*Use only on networks you own or are authorized to test.*
