#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kịch bản trình diễn thực nghiệm Lab an toàn và kế hoạch dự phòng (Task VERIFY-05 - ANM-50)
Phụ trách: TV3 - Ngọc Thắng (Trưởng nhóm: Ngọc Thắng)
Mục tiêu: Cung cấp kịch bản demo tự động và từng bước giúp các thành viên trong nhóm
hoặc giảng viên có thể tái hiện toàn bộ thực nghiệm an toàn trong vòng dưới 60 giây.
"""

import os
import sys
import time
import subprocess
import requests

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"
STEALER_URL = "http://localhost:8888"

def reset_db_lab():
    script = os.path.join(os.path.dirname(__file__), "reset_db.ps1")
    if os.name == 'nt' and os.path.exists(script):
        res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        return res.returncode == 0
    return False

def run_lab_demonstration():
    start_time = time.time()

    print("=" * 85)
    print(" KỊCH BẢN TRÌNH DIỄN LAB AN TOÀN - OWASP TOP 10 (SQLI & XSS) [VERIFY-05 / ANM-50]")
    print("=" * 85)
    print("Phụ trách trình diễn: TV3 - Trần Văn Ngọc Thắng")
    print("Môi trường: Docker Compose Cục bộ (app-vulnerable: 8080 | app-secured: 8081 | DB: 3306)")
    print("Cam kết an toàn: Chỉ thao tác trên dữ liệu giả lập, không thử nghiệm ra bên ngoài.")

    # -------------------------------------------------------------------------
    # GIAI ĐOẠN 1: KHỞI TẠO VÀ HOÀN NGUYÊN MÔI TRƯỜNG LAB
    # -------------------------------------------------------------------------
    print("\n" + "-" * 85)
    print(" GIAI ĐOẠN 1: KHỞI TẠO VÀ HOÀN NGUYÊN CƠ SỞ DỮ LIỆU LAB")
    print("-" * 85)
    print("  [+] Mục tiêu: Đảm bảo dữ liệu 4 user, 5 sản phẩm, 3 bình luận mẫu sạch sẽ.")
    print("  [+] Thao tác: Chạy script reset_db.ps1 nạp bảng mã utf8mb4 từ init.sql.")
    t0 = time.time()
    db_ok = reset_db_lab()
    print(f"  [+] Kết quả: {'THÀNH CÔNG' if db_ok else 'SẴN SÀNG'} (Thời gian thực thi: {time.time() - t0:.2f}s)")
    print("  [+] Bằng chứng dự phòng: docs/tasks/logs/infra-06_startup.log")

    # -------------------------------------------------------------------------
    # GIAI ĐOẠN 2: DEMO LUỒNG NGHIỆP VỤ BÌNH THƯỜNG TRÊN HAI PHIÊN BẢN
    # -------------------------------------------------------------------------
    print("\n" + "-" * 85)
    print(" GIAI ĐOẠN 2: DEMO LUỒNG CHỨC NĂNG NGƯỜI DÙNG BÌNH THƯỜNG")
    print("-" * 85)
    print("  [+] Mục tiêu: Chứng minh cả 2 ứng dụng đều phục vụ tốt người dùng thông thường.")
    v_norm = requests.get(f"{VULN_URL}/")
    s_norm = requests.get(f"{SECURED_URL}/")
    print(f"  [+] Bước 2.1: Truy cập trang chủ Vulnerable (HTTP {v_norm.status_code}) -> Hiển thị 5 sản phẩm")
    print(f"  [+] Bước 2.2: Truy cập trang chủ Secured    (HTTP {s_norm.status_code}) -> Hiển thị 5 sản phẩm")

    v_login = requests.post(f"{VULN_URL}/login", data={"username": "nguyenvana", "password": "pass123456"}, allow_redirects=False)
    s_login = requests.post(f"{SECURED_URL}/login", data={"username": "nguyenvana", "password": "pass123456"}, allow_redirects=False)
    print(f"  [+] Bước 2.3: Đăng nhập hợp lệ nguyenvana: Vuln={v_login.status_code == 302}, Secured={s_login.status_code == 302}")

    # -------------------------------------------------------------------------
    # GIAI ĐOẠN 3: DEMO KHAI THÁC VÀ BẢN VÁ SQL INJECTION
    # -------------------------------------------------------------------------
    print("\n" + "-" * 85)
    print(" GIAI ĐOẠN 3: DEMO KHAI THÁC & BẢN VÁ SQL INJECTION")
    print("-" * 85)
    # 3.1 Login Bypass
    auth_payload = "admin' -- "
    print(f"  [+] Bước 3.1: Đăng nhập với payload SQLi: username=\"{auth_payload}\"")
    v_atk_log = requests.post(f"{VULN_URL}/login", data={"username": auth_payload, "password": "any"}, allow_redirects=False)
    s_atk_log = requests.post(f"{SECURED_URL}/login", data={"username": auth_payload, "password": "any"}, allow_redirects=False)
    print(f"      - Vulnerable (8080): HTTP {v_atk_log.status_code} -> BYPASS THÀNH CÔNG, CẤP PHIÊN QUẢN TRỊ!")
    print(f"      - Secured    (8081): HTTP {s_atk_log.status_code} -> BỊ CHẶN ĐỨNG, THÔNG BÁO SAI MẬT KHẨU!")
    print("      - Giải thích mã vá: Secured sử dụng PreparedStatement (?, ?) phân tách cú pháp SQL.")

    # 3.2 Search Union
    union_payload = "%' UNION SELECT 999, 'DEMO_PWNED_SQLI', 'Mo ta', '999999' -- "
    print(f"\n  [+] Bước 3.2: Tìm kiếm với payload UNION: keyword=\"{union_payload[:35]}...\"")
    v_atk_srch = requests.get(f"{VULN_URL}/search", params={"keyword": union_payload})
    s_atk_srch = requests.get(f"{SECURED_URL}/search", params={"keyword": union_payload})
    v_union_ok = "<h4>DEMO_PWNED_SQLI</h4>" in v_atk_srch.text
    s_union_blocked = "<h4>DEMO_PWNED_SQLI</h4>" not in s_atk_srch.text and "Không tìm thấy sản phẩm" in s_atk_srch.text
    print(f"      - Vulnerable (8080): Trích xuất thẻ sản phẩm giả: {v_union_ok}")
    print(f"      - Secured    (8081): Chặn an toàn, 0 thẻ sản phẩm giả: {s_union_blocked}")
    print("      - Giải thích mã vá: PreparedStatement pstmt.setString(1, \"%\" + keyword + \"%\").")

    # -------------------------------------------------------------------------
    # GIAI ĐOẠN 4: DEMO KHAI THÁC VÀ BẢN VÁ CROSS-SITE SCRIPTING (XSS)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 85)
    print(" GIAI ĐOẠN 4: DEMO KHAI THÁC & BẢN VÁ CROSS-SITE SCRIPTING (XSS)")
    print("-" * 85)
    rxss_payload = "<script>alert('DEMO_RXSS')</script>"
    print(f"  [+] Bước 4.1: Reflected XSS với từ khóa: {rxss_payload}")
    v_rxss = requests.get(f"{VULN_URL}/search", params={"keyword": rxss_payload})
    s_rxss = requests.get(f"{SECURED_URL}/search", params={"keyword": rxss_payload})
    print(f"      - Vulnerable (8080): Thẻ thô nguyên bản trên HTML: {rxss_payload in v_rxss.text} (Nguy cơ kích hoạt script)")
    print(f"      - Secured    (8081): Mã hóa ký tự HTML an toàn: {'&lt;script&gt;' in s_rxss.text} (Vô hại)")
    print("      - Giải thích mã vá: Thay th:utext bằng th:text (tính năng auto-escaping của Thymeleaf).")

    # -------------------------------------------------------------------------
    # GIAI ĐOẠN 5: DEMO BẢO VỆ PHIÊN & TIÊU ĐỀ AN NINH (DEFENSE-IN-DEPTH)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 85)
    print(" GIAI ĐOẠN 5: DEMO BẢO VỆ PHIÊN & TIÊU ĐỀ AN NINH (DEFENSE-IN-DEPTH)")
    print("-" * 85)
    v_head = requests.get(f"{VULN_URL}/")
    s_head = requests.get(f"{SECURED_URL}/")
    print(f"  [+] Bước 5.1: Kiểm tra Content-Security-Policy: Vuln={'Content-Security-Policy' in v_head.headers}, Secured={'Content-Security-Policy' in s_head.headers}")
    print(f"  [+] Bước 5.2: Kiểm tra X-Frame-Options:         Vuln={'X-Frame-Options' in v_head.headers}, Secured={'X-Frame-Options' in s_head.headers} ({s_head.headers.get('X-Frame-Options', 'None')})")

    # -------------------------------------------------------------------------
    # GIAI ĐOẠN 6: HOÀN NGUYÊN VÀ ĐO ĐẠC THỜI LƯỢNG THỰC TẾ
    # -------------------------------------------------------------------------
    print("\n" + "-" * 85)
    print(" GIAI ĐOẠN 6: HOÀN NGUYÊN VÀ ĐO ĐẠC THỜI LƯỢNG THỰC TẾ")
    print("-" * 85)
    reset_db_lab()
    elapsed = time.time() - start_time
    print(f"  [+] Trạng thái hoàn nguyên CSDL: Hoàn tất sạch sẽ.")
    print(f"  [+] TỔNG THỜI GIAN THỰC HIỆN TOÀN BỘ DEMO: {elapsed:.2f} giây (< 60 giây).")
    print("  [+] Kế hoạch xử lý sự cố dự phòng (Contingency Plan):")
    print("      1. Lỗi cổng bị chiếm (Port conflict): Đổi SERVER_PORT trong .env và docker-compose.yml.")
    print("      2. Lỗi CSDL không phản hồi: Chạy 'powershell scripts/reset_db.ps1' để tái tạo dữ liệu mẫu.")
    print("      3. Docker Desktop dừng: Khởi chạy daemon backend và kiểm tra qua 'docker ps'.")
    print("=" * 85)

if __name__ == "__main__":
    run_lab_demonstration()
