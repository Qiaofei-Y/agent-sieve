.PHONY: demo test selftest compile clean help

help:
	@echo "make demo      — 跑 S0/S2/S3 的 --demo"
	@echo "make test      — 编译检查 + 自测 + 评估"
	@echo "make selftest  — golden 集回归（断言 FP=0 FN=0）"
	@echo "make clean     — 清理 __pycache__ 与运行时状态"

demo:
	python3 sieve-s0/sieve_s0.py --demo --no-color
	python3 sieve-s1/sieve_s1.py --demo --no-color
	python3 sieve-s2/sieve_s2.py --demo --no-color
	python3 sieve-s3/sieve_s3.py --demo --no-color

compile:
	python3 -m py_compile sieve-s0/sieve_s0.py sieve-s1/sieve_s1.py sieve-s2/sieve_s2.py \
		sieve-s3/sieve_s3.py sieve-verify/evaluate.py \
		sieve-verify/run_attacks.py scripts/selftest.py

selftest:
	python3 scripts/selftest.py

test: compile selftest
	python3 sieve-verify/evaluate.py --no-color

clean:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
	rm -f sieve-*/sieve_*state.json sieve-verify/attack_manifest.jsonl
