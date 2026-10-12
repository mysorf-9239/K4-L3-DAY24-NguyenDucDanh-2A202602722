# DPIA-lite — CP5

1. Loại dữ liệu và phân loại: ticket là dữ liệu untrusted/internal; hồ sơ
   customer trong `data/customers.json` là synthetic/restricted và gồm CCCD,
   điện thoại, STK, email.
2. Mục đích xử lý và principal: `support_l1` tổng hợp ticket nhưng không được
   đọc hồ sơ restricted; `dpo` được đọc hồ sơ liên quan cho `support-reply`.
3. Dữ liệu đi qua những run/tool nào: Run A gọi `search_docs`; chỉ ticket ID
   từ filename đi sang Run B. Run B map qua `related_tickets`, kiểm policy
   trước `read_customer`, rồi kiểm riêng `http_post` tới sink localhost.
4. Bằng chứng deny/allow và giới hạn: ledger có allow/deny kèm reason và hash
   chain; `attack-after.log` phải rỗng. Đây chỉ là lab với `--mock`, principal
   mô phỏng, regex PII và ledger một file; không phải authentication hay đánh
   giá tác động pháp lý production.
