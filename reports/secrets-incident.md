# Secret giả trong lịch sử Git — CP4

- Scanner và phiên bản: Gitleaks v8.30.1.
- Commit chứa token giả: `1bdd849`.
- File, rule và kết quả quét lịch sử: Gitleaks quét Git history và trả exit 1
  với đúng một finding của rule `lab24-synthetic-token`; output đã dùng
  `--redact`, không ghi token nguyên văn vào báo cáo.
- Kết quả quét file hiện tại: `gitleaks dir --config .gitleaks.toml --redact .`
  trả exit 0, không phát hiện leak.
- Nếu đây là credential thật, phải kiểm tra việc sử dụng sai, revoke/rotate
  ngay tại dịch vụ cấp token và xử lý mọi bản sao/log/cache liên quan.
- Xóa file khỏi HEAD không thu hồi credential đã lộ; pin dependency và hook
  chỉ giảm rủi ro phát sinh mới, không thay thế việc rotate secret.
