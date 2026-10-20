# Changelog

[简体中文](CHANGELOG.md) · **English**

All notable changes to this project are recorded here, following
[Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **S0** DNS-layer detector (Pi-hole query log → LLM/agent/DoH domain matching + scoring + Telegram).
- **S1** crawler-authenticity-verification component (inbound access logs → requests claiming to be AI crawlers verified against vendors' official IP-range JSON; classified as verified / spoofed / unverifiable).
- **S2** TLS-fingerprint detector (Zeek + JA4 → script/browser classification + beaconing + large egress).
- **S3** merge-verdict layer (S2 as primary judge + ≥2 signal families + human guardrail;
  FP=0 FN=0 on the golden set).
- **sieve-verify** accuracy-evaluation framework + labeled golden set with false-positive traps +
  real-network self-test traffic generator.
- Docs: purple-team playbook, interactive validation runbook, console design.
- `scripts/selftest.py` regression test, Makefile, GitHub Actions CI.
- OSS community meta files: `CODE_OF_CONDUCT.md` (+ `.en.md`), PR template, issue-template config, `.editorconfig`.

### To do
- Real-network validation, produce measured precision.
- Cross-tenant domain-reputation / JA4-fingerprint DB.
