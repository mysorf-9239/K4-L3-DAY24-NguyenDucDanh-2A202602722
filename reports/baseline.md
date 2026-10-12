# Baseline — CP1

1. Chưa có identity riêng cho mỗi run. `_naive_loop()` chỉ nhận `message` và
   `llm`, sau đó gọi tools trực tiếp; không tạo `agent_id`, `run_id` hay
   principal nào (`agent/loop.py:27-54`).
2. Không có policy kiểm mục đích, quyền hoặc loại dữ liệu trước khi gửi.
   `_naive_loop()` lấy customer ID từ injection rồi gọi `read_customer()`
   (`agent/loop.py:37-40`), sau đó tự gọi `http_post()` (`agent/loop.py:43-44`).
   `agent/tools.py:68-85` chỉ allowlist host/port localhost, không quyết định
   dữ liệu nào được gửi.
3. Body POST được tạo tại `agent/loop.py:44` dưới dạng
   `{"records": collected}`. Sink ghi mỗi request thành một dòng JSON vào
   `reports/sink.log` (`sink/sink.py:45-47`), nên log đó là bằng chứng payload
   đã tới sink.
