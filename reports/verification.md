# Verification — CP5

- OS / Python / Gitleaks version: macOS; Python 3.14.7; Gitleaks 8.30.1.
- `python -m pytest tests/ -q --basetemp=.pytest_tmp`: **33 passed**.
- `pre-commit run --all-files`: **Passed — Detect hardcoded secrets**.
- Ledger verify: **True** for `reports/ledger.jsonl`.
- PII: gold=118, pred=118, tp=118, precision=1.000, recall=1.000.
- Baseline: 4/4 lure sẵn sàng; `attack-before.log` đã có 4 POST synthetic.
- Attack evidence: `attack-before.log` = 4 JSONL POST lines; `attack-after.log`
  = 0 bytes. Safe `dpo` replay produced a denied `http_post` ledger entry.
- Các lỗi còn lại: `python` alias không có trong PATH trên máy này nên dùng
  `.venv/bin/python`; sandbox không cho bind localhost nên sink/test chạy qua
  quyền local được phê duyệt. Không có test failure còn lại.
