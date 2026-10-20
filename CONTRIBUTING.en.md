# Contributing

[简体中文](CONTRIBUTING.md) · **English**

Thanks for taking part in Sieve. Code, domain lists, and fingerprint annotations are all valuable.

## Code of conduct

Test only on networks you own or are authorized to test. Any use against third parties, other
people's devices, or unauthorized targets is unacceptable; such PRs / issues will be closed.

## Most-wanted contributions

1. **Domain list** ([`sieve-s0/domains.txt`](sieve-s0/domains.txt)) — add new LLM API, agent
   infrastructure, and DoH resolver domains. A source reference is ideal.
2. **JA4 fingerprints** — browser / script JA4s you've confirmed on your own network (note the
   client and version).
3. **False-positive / false-negative cases** — with the (redacted) signal combination, to help
   improve the verdict rules.

## Development conventions

- **Pure standard library**: no third-party dependencies, so it keeps running out of the box on a
  Raspberry Pi.
- **Single source of truth**: S3 / verify import S0/S2's scoring functions directly — don't rewrite
  the scoring logic.
- After changing scoring logic, always run the selftest:
  ```bash
  python3 scripts/selftest.py        # must report FP=0 FN=0
  make demo                          # all four demos should produce normal output
  ```
- Code style: follow the existing files' comment density and bilingual-comment conventions.

## PR workflow

1. Fork & branch.
2. Make changes + run `make test`.
3. In the PR description, state: what changed, why, and whether it affects
   `scripts/selftest.py` results.

## Issues

- **Bug**: include repro steps and `--demo` or redacted real output.
- **False positive / negative**: use the issue template, include the signal-family combination
  (no real sensitive data).

## Security issues

Do not use public issues — see [SECURITY.md](SECURITY.md).
