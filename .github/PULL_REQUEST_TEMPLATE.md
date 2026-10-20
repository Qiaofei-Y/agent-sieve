<!-- 中英对照 · Bilingual (CN / EN) -->

## 改了什么 / What changed



## 为什么 / Why



## 自查清单 / Checklist

- [ ] 跑过 `python3 scripts/selftest.py`，结果仍为 **FP=0 FN=0** / Ran `python3 scripts/selftest.py`, still reports **FP=0 FN=0**
- [ ] `make demo` 的 demo 均正常输出 / All `make demo` demos still produce normal output
- [ ] 保持**纯标准库**，未引入第三方依赖 / Stays **stdlib-only**, no third-party dependencies added
- [ ] 未重写 S0/S2 的打分逻辑（S3 / verify 仍直接 import）/ Did not rewrite S0/S2 scoring logic (S3 / verify still import it)
- [ ] 若改动了文档，中英两份（`X.md` / `X.en.md`）已同步 / If docs changed, the CN and EN copies (`X.md` / `X.en.md`) are in sync
- [ ] 未粘贴真实敏感数据（内部域名、IP、凭据）/ No real sensitive data (internal domains, IPs, credentials)

## 对检测结果的影响 / Impact on detection results

<!-- 若影响打分或研判，请说明；否则写“无” -->
<!-- If scoring or verdicts are affected, describe it; otherwise write "none" -->
