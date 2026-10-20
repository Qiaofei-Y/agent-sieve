# Sieve S1 — Crawler authenticity verification (vendor official IP ranges)

[简体中文](README.md) · **English**

> Stage 1 prototype. Against the access logs of a publicly exposed service
> (reverse proxy / NAS / blog), it finds requests **claiming to be AI crawlers**
> (UA containing GPTBot / ClaudeBot / PerplexityBot, etc.) and verifies, using each
> vendor's **officially published IP-range JSON**, whether the source IP truly belongs
> to that vendor — a UA claiming GPTBot whose IP is not in the official ranges = impersonation.
>
> **Pure Python standard library, no `pip install`, runs out of the box on Mac / Raspberry Pi.**

Companion docs in the parent `docs/` (purple-team playbook, console design).

---

## What it does / doesn't

| Does | Doesn't |
|---|---|
| Verify that a self-declared AI crawler's source IP is in the vendor's official ranges | See crawlers that don't declare themselves (UA faked as a normal browser) |
| Catch traffic impersonating GPTBot/ClaudeBot/Perplexity to scrape or scan your site | Block anything — it only judges; enforcement is up to your firewall / rate limiter |
| Verify dynamically from vendor JSON, no hardcoded IPs, with cache and timeout | Parse encrypted content, or touch LAN devices (that's S0 / S2) |

S1's vantage point is **your own service's access log** (inbound), complementing S0 (DNS, outbound) and S2 (TLS fingerprints).

---

## See it in 30 seconds (no real log needed, runs on a Mac)

```bash
python3 sieve_s1.py --demo
```

It synthesizes an access log and injects "official ranges" in memory (no network), printing something like:

```
Sieve S1 · 爬虫真伪核验报告   日志请求=9   自称爬虫=7
合计: verified=3 · spoofed=3 · unverifiable=1
------------------------------------------------------------------
GPTBot           (OpenAI)  verified=2 spoofed=2 unverifiable=0  源:demo
    [冒充] 45.137.21.9      "GET /wp-login.php HTTP/1.1"
    [冒充] 45.137.21.9      "POST /xmlrpc.php HTTP/1.1"
ClaudeBot        (Anthropic)  verified=0 spoofed=0 unverifiable=1  源:段取不到
    [无法核验] 185.220.101.5    "GET /docs/ HTTP/1.1"
PerplexityBot    (Perplexity)  verified=1 spoofed=1 unverifiable=0  源:demo
    [冒充] 103.224.182.251  "GET /.env HTTP/1.1"
------------------------------------------------------------------
⚑ 发现 3 条冒充 AI 爬虫的请求 —— 建议结合防火墙/速率限制处置。
```

- **verified**: real crawler (real UA + IP inside official ranges).
- **spoofed**: impersonation (real UA but IP not in official ranges) — the ones to look at.
- **unverifiable**: official IP ranges couldn't be fetched this run (e.g. demo injects none for Anthropic) — it degrades and skips, does not crash.

---

## Real deployment (3 steps)

### 1. Prepare the access log
The log must be in **combined** format (with the User-Agent field — Nginx `log_format combined` / Apache `combined` is this by default).
The common format has no UA and cannot be verified; such lines are skipped.

> **Behind a reverse proxy / CDN?** Make sure the log records the **real client IP**, not the
> proxy's internal IP (Nginx `set_real_ip_from` + `real_ip_header X-Forwarded-For`, or put XFF
> in the first log field). Otherwise you verify the proxy IP and everything looks spoofed.

### 2. Put it on the server, copy the config
```bash
cp config.example.json config.json
# edit config.json: confirm log_path, add/remove bots, tune cache TTL as needed
python3 sieve_s1.py --observe
```

The first run fetches IP ranges from each vendor's official URL and caches them under `.cache/` (default TTL 24h).
If a fetch fails, that bot is marked unverifiable with a notice — it **never crashes**.

### 3. Turn on alerts once you have a rhythm
```bash
export SIEVE_TG_TOKEN="123456:ABC..."     # Telegram setup: see the S0 README
export SIEVE_TG_CHAT="your chat id"
python3 sieve_s1.py --alert
```

Works without Telegram too — `--alert` prints the alert content but skips the push.

---

## Scheduling (cron, hourly)

```cron
0 * * * * SIEVE_TG_TOKEN=... SIEVE_TG_CHAT=... /usr/bin/python3 /opt/sieve-s1/sieve_s1.py --log /var/log/nginx/access.log --alert >> /var/log/sieve-s1.log 2>&1
```

> To look at recent logs only, rotate with `logrotate`, or `tail` the log and feed it to `--log`.

---

## Command line

```
--demo                 synthesize a log and demo it, no real log, no network
--observe              print only, no alert (default)
--alert                push Telegram when impersonations exceed threshold
--log PATH             access-log path (overrides log_path in config)
--config PATH          config file (default ./config.json)
--rdns                 add forward-confirmed rDNS (FCrDNS) enhancement
--refresh-cache        ignore local cache and re-fetch official IP ranges
--no-color             disable colored output
```

---

## Verification logic

1. **Pick out self-declared crawlers**: parse the log line by line; a UA matching `bots[].ua_tokens` (substring, case-insensitive) counts as "claiming to be that bot".
2. **Fetch the vendor's official ranges**: for that bot's `ip_json_urls`, fetch the JSON with `urllib` (with timeout) and cache locally (`cache_dir`, served directly within `cache_ttl_hours`). On failure, fall back to stale cache; if none, mark unverifiable.
3. **Parse CIDRs**: with `ipaddress`, recursively pull every network out of fields like `ipv4Prefix / ipv6Prefix / prefix / cidr / ip` (tolerant of each vendor's format, no hardcoded IPs).
4. **Compare the source IP**:
   - IP ∈ official ranges → **verified**
   - IP ∉ official ranges → **spoofed** (alert)
   - ranges unavailable → **unverifiable** (degrade)
5. **Optional FCrDNS** (`--rdns`): reverse-lookup the IP; it passes only if the PTR ends with the vendor's domain suffix and forward-resolves back to the same IP. It's an annotation, not the primary verdict (IP ranges win).

---

## Fields (vendor official JSON URLs)

| Vendor | UA token | Official IP JSON |
|---|---|---|
| OpenAI | GPTBot | https://openai.com/gptbot.json |
| OpenAI | OAI-SearchBot | https://openai.com/searchbot.json |
| OpenAI | ChatGPT-User | https://openai.com/chatgpt-user.json |
| Anthropic | ClaudeBot, etc. | https://claude.com/crawling/bots.json |
| Perplexity | PerplexityBot | https://www.perplexity.ai/perplexitybot.json |
| Perplexity | Perplexity-User | https://www.perplexity.ai/perplexity-user.json |

> These URLs are vendor-maintained and change occasionally; maintain them in `bots` in your `config.json` — never hardcode IPs in the code.

Config keys: `log_path`, `cache_dir`, `cache_ttl_hours`, `fetch_timeout_seconds`, `enable_rdns`, `spoof_alert_threshold` (impersonations per bot that trigger an alert), `alert_cooldown_minutes`, `telegram`, `bots`.

---

## Files

| File | Purpose |
|---|---|
| `sieve_s1.py` | Main program |
| `config.example.json` | Config template, copy to `config.json` |
| `.cache/` | Auto-generated: cached vendor official IP-range JSON (not committed) |
| `sieve_s1_state.json` | Auto-generated: alert cooldown record (not committed) |

---

## Next steps (per the playbook)

- **S0**: Pi-hole DNS layer — catch LAN devices hitting LLM / agent (outbound).
- **S2**: Zeek + JA4 TLS fingerprints — catch script clients and beaconing.
- **S3**: merge the S0 / S1 / S2 verdicts into one judgement.

---

*Use only on networks you own or are authorized to test.*
