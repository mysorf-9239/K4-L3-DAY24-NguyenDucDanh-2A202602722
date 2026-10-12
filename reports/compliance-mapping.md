# Compliance mapping — CP5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=214590&pageid=27160&typegroupid=3) | PII detection/redaction, policy-before-tool và audit ledger | `agent/pii.py:44-90`, `agent/policy.py:61-96`, `agent/ledger.py:54-91` | Chưa đối chiếu điều khoản cụ thể; lab không phải chứng nhận tuân thủ. |
| [NĐ 356/2025/NĐ-CP](https://vanban.chinhphu.vn/?classid=1&docid=216387&pageid=27160) | Tách dữ liệu untrusted/private, kiểm principal/scope/TTL và deny egress | `agent/runner.py:127-176`, `data/principals.json:2-4` | Chưa đối chiếu điều khoản cụ thể. |
| [Luật AI 134/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=216334&orggroupid=1&pageid=27160) | Containment trước khi tool xử lý dữ liệu, logging quyết định và giới hạn mock | `agent/runner.py:108-125`, `reports/ledger.jsonl` | Chưa đối chiếu điều khoản cụ thể; không suy ra compliance production. |
| [OWASP GenAI](https://genai.owasp.org/) — ASI01/03/04 | Prompt-injection replay, least privilege/OBO, split boundary và egress deny | `corpus/ticket-90*.md`, `tests/test_injection.py:69-142`, `tests/test_split.py:75-115` | Mapping học tập; chưa phải đánh giá OWASP độc lập. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
