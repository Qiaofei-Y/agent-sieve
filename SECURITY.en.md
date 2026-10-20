# Security Policy

[简体中文](SECURITY.md) · **English**

## Reporting a vulnerability

**Do not** report security vulnerabilities through public issues.

Please contact the maintainer privately:

- GitHub Security Advisory: this repo's **Security → Report a vulnerability** (preferred)
- or email: `<fill in your security contact email>`

Please include: affected component (S0/S2/S3/verify), repro steps, potential impact.
We'll respond within a reasonable time and coordinate a fix and disclosure.

## Usage boundary (important)

Sieve is a **defensive** tool for detecting anomalous AI/agent traffic on networks you own or are
authorized to test.

- Its `run_attacks.py` generates test traffic, **only against your own devices / authorized targets**.
- By default it only performs TLS handshakes or unauthenticated small requests; it sends no real
  data, does no port scanning, and does not touch third parties.
- Any use of this project for unauthorized monitoring, attacking third parties, or circumventing
  others' security controls is outside its intended purpose — the risk and responsibility are
  entirely your own.

## Privacy

- On the network side Sieve handles **metadata only** (domains, IPs, TLS fingerprints, traffic
  timing/size); it does not decrypt content by default.
- Deploying on a corporate network involves monitoring employee traffic — complete your internal
  privacy/compliance review and obtain informed consent first.
