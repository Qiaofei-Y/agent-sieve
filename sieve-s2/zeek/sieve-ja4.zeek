# Sieve S2 — Zeek 站点配置
# =========================
# 作用：让 conn.log / ssl.log 以 JSON 输出，并加载 JA4 包，
#       使 ssl.log 带上 ja4 指纹字段，供 sieve_s2.py 分析。
#
# 前置：先用 zkg 安装官方 JA4 包（见 README）：
#     sudo zkg install zeek/ja4
#
# 起监听（示例）：
#     sudo zeek -i eth0 -C /opt/sieve-s2/zeek/sieve-ja4.zeek
# 日志默认写到当前目录，交给 sieve_s2.py --logs 指向即可。

@load policy/tuning/json-logs    # 所有日志改为 JSON（每行一条）

# 加载 JA4 包：zkg 安装后通过 packages 汇总加载
@load packages
# 若未用 zkg 的 packages 汇总，可改为显式路径：
# @load ja4

# ── 可选调优 ──────────────────────────────────────────────

# ssl.log 里保留我们关心的字段（JA4 包会自动加 ja4 列）
# conn.log 默认已含 orig_bytes / resp_bytes / duration，够用。

# 只记真正建立起来的连接，减噪（按需放开）
# redef ignore_checksums = T;

# 把本机/内网互联排除，降低噪声（按你的网段改）
# 这里不做默认过滤，交给 sieve_s2.py 的 local_nets 处理，便于集中配置。

event zeek_init()
    {
    print "Sieve S2 · Zeek 已启动，JSON 日志 + JA4 指纹已启用。";
    }
