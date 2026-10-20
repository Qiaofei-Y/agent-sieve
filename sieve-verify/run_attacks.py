#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sieve Verify — 真实网络自测流量生成器（紫队 T1–T7）
====================================================

在**你自己的**网络里，从当前这台机器发出带标注的测试流量，让部署在网内的
S0 / S2 去观测，再用 evaluate.py --from-live 比对，算出真实误报/漏报。

安全约束（务必遵守）：
  · 只对你拥有或已获授权的目标执行；默认只做 TLS 握手 / 未授权小请求，不发真实数据。
  · 任何需要目标的测试（扫描/回连）都必须显式 --target，且应指向你自己的主机。
  · 不做端口扫描、不打第三方、不传任何敏感内容。

每次运行写一条 manifest 记录（时间窗 + 标注），供 evaluate.py 对齐。

用法：
    python3 run_attacks.py --list
    python3 run_attacks.py --test t1            # 影子外泄：python 直连 LLM API（握手+401）
    python3 run_attacks.py --test t4            # DoH 绕过：向 DoH 解析器发查询
    python3 run_attacks.py --test t6 --target 192.168.1.9   # 回连：等间隔连你自己的主机
    python3 run_attacks.py --test t2 --target https://你自己的内网站点/

仅用于你拥有或已获授权的网络。
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "attack_manifest.jsonl")

LLM_HOSTS = ["api.openai.com", "api.anthropic.com", "api.deepseek.com"]
DOH_HOST = "cloudflare-dns.com"

TESTS = {
    "t1": ("影子外泄", "malicious", "python 脚本直连 LLM API（TLS 握手 + 未授权请求，不发数据）"),
    "t2": ("脚本扒站", "malicious", "python 循环 GET 你自己的目标（需 --target），制造脚本指纹+扇出"),
    "t4": ("DoH 绕过", "malicious", "向 DoH 解析器发加密 DNS 查询"),
    "t6": ("C2 回连", "malicious", "等间隔连你自己的 --target，制造 beaconing"),
    "b1": ("对照·正常", "benign", "对照组：普通 HTTPS 访问若干正常站点（应不被告警）"),
}


def record(test, label, note, t0, t1, extra=None):
    rec = {"ts_start": int(t0), "ts_end": int(t1), "test": test,
           "label": label, "note": note, "host": socket.gethostname()}
    if extra:
        rec.update(extra)
    with open(MANIFEST, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("✓ 已记录到 manifest：%s [%s] %s" % (test, label, note))


def tls_touch(host, port=443, send_probe=True):
    """与 host 完成 TLS 握手（python 的 JA4），可选发一个未授权小请求。"""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                if send_probe:
                    ss.sendall(("GET /v1/models HTTP/1.1\r\nHost: %s\r\n"
                                "Connection: close\r\n\r\n" % host).encode())
                    ss.recv(64)  # 多半是 401，丢弃
        print("    · 已握手 %s（python TLS 指纹）" % host)
        return True
    except Exception as e:  # noqa: BLE001
        print("    · %s 连接失败（不影响测试意图）：%s" % (host, e))
        return False


def do_t1():
    t0 = time.time()
    for h in LLM_HOSTS:
        tls_touch(h)
    record("t1", "malicious", TESTS["t1"][2], t0, time.time())


def do_t2(target):
    if not target:
        sys.exit("t2 需要 --target（指向你自己的内网站点，如 https://10.0.0.9/）")
    t0 = time.time()
    for i in range(15):
        try:
            req = urllib.request.Request(target + ("?p=%d" % i),
                                         headers={"User-Agent": "python-urllib/sieve-test"})
            urllib.request.urlopen(req, timeout=6).read(64)
        except Exception as e:  # noqa: BLE001
            print("    · 请求 %d 失败：%s" % (i, e))
        time.sleep(0.3)
    record("t2", "malicious", TESTS["t2"][2], t0, time.time(), {"target": target})


def do_t4():
    t0 = time.time()
    # 向 DoH 解析器发一个 RFC 8484 GET 查询（application/dns-message）
    # 这里用更简单的 JSON API 形式，足以在网络上留下"连 DoH 解析器"的痕迹
    url = "https://%s/dns-query?name=example.com&type=A" % DOH_HOST
    try:
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        urllib.request.urlopen(req, timeout=8).read(128)
        print("    · 已向 %s 发 DoH 查询" % DOH_HOST)
    except Exception as e:  # noqa: BLE001
        print("    · DoH 查询失败（握手痕迹可能已产生）：%s" % e)
    record("t4", "malicious", TESTS["t4"][2], t0, time.time())


def do_t6(target, count, interval):
    if not target:
        sys.exit("t6 需要 --target（指向你自己的主机，如 192.168.1.9）")
    host = target
    port = 443
    if ":" in target:
        host, p = target.rsplit(":", 1); port = int(p)
    t0 = time.time()
    print("    · 向 %s:%d 等间隔回连 %d 次，间隔 %ds" % (host, port, count, interval))
    for i in range(count):
        try:
            socket.create_connection((host, port), timeout=5).close()
        except Exception as e:  # noqa: BLE001
            print("    · 第 %d 次失败：%s" % (i, e))
        if i < count - 1:
            time.sleep(interval)
    record("t6", "malicious", TESTS["t6"][2], t0, time.time(),
           {"target": target, "count": count, "interval": interval})


def do_b1():
    t0 = time.time()
    for h in ["github.com", "www.apple.com", "www.wikipedia.org"]:
        tls_touch(h, send_probe=False)
    record("b1", "benign", TESTS["b1"][2], t0, time.time())


def main():
    ap = argparse.ArgumentParser(description="Sieve Verify — 真实网络自测流量生成器")
    ap.add_argument("--list", action="store_true", help="列出可用测试")
    ap.add_argument("--test", help="要运行的测试：t1/t2/t4/t6/b1")
    ap.add_argument("--target", help="你自己的目标（t2 用 URL，t6 用 host[:port]）")
    ap.add_argument("--count", type=int, default=10, help="t6 回连次数")
    ap.add_argument("--interval", type=int, default=30, help="t6 回连间隔秒")
    ap.add_argument("--yes", action="store_true", help="确认已获授权，跳过提示")
    args = ap.parse_args()

    if args.list or not args.test:
        print("可用测试（T3/T5/T7 见手册，涉及外部工具或真实 agent，需手动执行）：")
        for k, (name, label, note) in TESTS.items():
            print("  %-4s [%s] %s —— %s" % (k, label, name, note))
        print("\n运行示例： python3 run_attacks.py --test t1 --yes")
        return

    if not args.yes:
        ans = input("确认目标网络由你拥有或已获授权？(yes/no) ").strip().lower()
        if ans != "yes":
            sys.exit("已取消。")

    t = args.test.lower()
    print("\n运行 %s …（%s）" % (t, TESTS.get(t, ("?",))[0]))
    if t == "t1":
        do_t1()
    elif t == "t2":
        do_t2(args.target)
    elif t == "t4":
        do_t4()
    elif t == "t6":
        do_t6(args.target, args.count, args.interval)
    elif t == "b1":
        do_b1()
    else:
        sys.exit("未知测试：%s（用 --list 查看）" % t)
    print("完成。接着在网内机器跑：evaluate.py --from-live 比对检测结果。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
