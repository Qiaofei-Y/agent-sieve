# Sieve Reputation — cross-tenant reputation DB (the moat)

[简体中文](README.md) · **English**

> A single install only sees locally. Aggregate each install's **locally-flagged public
> indicators** (public LLM/scraper domains, JA4 fingerprints) by **de-duplicated tenant count**
> into one reputation feed, and every install consumes it — "flagged once, warned everywhere".
> The more people use it, the sharper it gets: a network-effect moat.
>
> **Pure Python standard library. Privacy-first, opt-in, poisoning-resistant.**

Consumed by [`../sieve-s3/`](../sieve-s3/) as an **optional additive signal** (with no feed, S3
behaves exactly as before).

---

## Why this is the moat

The code can be copied in two weeks; a year of cross-tenant-confirmed "bad domains + bad
fingerprints" from 1000 installs cannot. Value grows with the number of contributors and latecomers
can't catch up — this, not the detection code, is where Sieve is actually valuable.

## Three tools + one data flow

```
each install                 aggregator                each install
contribute.py  ──reports──▶  aggregate.py  ──feed──▶  sieve-s3 consumes
(privacy-filtered export)   (de-dup by tenant count)  (reputation signal)
```

- **`contribute.py`** — export locally-flagged indicators that belong to **public categories** as a
  sighting report.
- **`aggregate.py`** — merge many reports into a feed (`feed.json`) by **distinct tenant count**.
- **`reputation.py`** — the engine: feed read/write, integrity check, lookup, aggregation; reused by
  the above and by sieve-s3.

## 30-second demo (runs on a Mac)

```bash
python3 contribute.py --demo     # privacy filter: internal domains dropped, only public indicators exported
python3 aggregate.py  --demo     # network effect + anti-poisoning: a domain turns bad only after N tenants report it
python3 selftest.py              # regression selftest
# S3 consuming the feed (demo auto-loads feed.example.json):
python3 ../sieve-s3/sieve_s3.py --demo    # flagged devices get an extra "REP cross-tenant reputation hit"
```

## Privacy model (the crux of trust)

- **Export only the suspicious indicators themselves** (domain / JA4); **never** export internal
  domains, IPs, device identifiers, exact timestamps, browsing history, or any normal traffic.
- **Allowlist-style category filter**: only public categories (`llm_api / agent_infra /
  content_farm / scraper / doh_resolver / ja4_script`) may be exported; anything else (especially
  internal domains) is dropped — enforced at **both** the contribute and aggregate ends.
- **Opt-in**: `contribute.py` exports only when you run it.
- **Pseudonymous**: `tenant_id` is a locally-generated random pseudonym (in `.tenant_id`, not
  committed, no identifying info), used only for aggregation de-duplication.
- Time granularity is **monthly**, never exact timestamps.

## Anti-poisoning

- Reputation strength = number of **distinct tenants** reporting; the same tenant counts **once**
  per indicator — a single poisoner spamming 100 times still counts as 1 vote.
- Per-tenant per-run contribution is capped (`max_per_tenant`).
- An indicator is marked `bad` only after `confirm_min_tenants` (default 3) distinct tenants;
  otherwise it stays `suspicious` (does not trigger the S3 reputation signal).

## Integrity & distribution

- `feed.json` carries a content `sha256`; consumers verify it on load and warn on tampering.
- **Production should additionally GPG-sign the feed** before distribution (like a threat-intel
  subscription) — the hash guards against accidental corruption, the signature against
  man-in-the-middle replacement. This prototype does hash verification only.

## How S3 consumes it

With `reputation_feed` configured, sieve-s3 checks each device's domains/JA4s against the feed;
a hit on a **cross-tenant-confirmed bad** indicator adds an independent `rep` signal family
(default +30), marks `[REP]`, and raises confidence to high. It is **purely additive**: it only
strengthens verdicts and raises confidence, never suppresses existing logic, so it cannot create new
false negatives; with no feed, S3's behavior is unchanged.

## Files

| File | Purpose |
|---|---|
| `reputation.py` | Engine (feed read/write/verify/lookup/aggregate), reused by contribute/aggregate/sieve-s3 |
| `contribute.py` | Contributor end: privacy-first sighting export |
| `aggregate.py` | Aggregator end: cross-tenant de-dup into a feed |
| `feed.example.json` | Example feed (with a valid integrity hash) |
| `config.example.json` | Consumer config template |
| `selftest.py` | Regression selftest (privacy/de-dup/poisoning/integrity/lookup) |
| `.tenant_id` / `feed.json` / `reports/` | Runtime-generated, not committed |

## Next steps

- A real aggregation service (or decentralized signed-feed distribution).
- Contributor reputation weighting (older contributors weigh more, curbing sock-puppet poisoning).
- Indicator decay (down-weight stale `last_seen`).

---

*Use only on networks you own or are authorized to test.*
