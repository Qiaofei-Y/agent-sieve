# Changelog

本项目的所有重要变更记录于此。遵循 [Keep a Changelog](https://keepachangelog.com/)
与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- **S0** DNS 层检测器（Pi-hole 查询日志 → LLM/agent/DoH 域名匹配 + 打分 + Telegram）。
- **S2** TLS 指纹层检测器（Zeek + JA4 → 脚本/浏览器判定 + beaconing + 大外发）。
- **S3** 合并研判层（S2 主判 + ≥2 信号族 + 人类护栏；golden 集 FP=0 FN=0）。
- **sieve-verify** 准确率评估框架 + 带误报陷阱的 golden 标注集 + 真实网络自测流量生成器。
- 文档：攻防手册、交互式验证运行手册、控制台设计稿。
- `scripts/selftest.py` 回归自测、Makefile、GitHub Actions CI。

### 待办
- 真实网络验证，产出实测精确率。
- S1 爬虫真伪核验。
- 跨客户域名信誉库 / JA4 指纹库。
