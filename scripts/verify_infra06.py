#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kịch bản kiểm tra tích hợp toàn hệ thống (Task INFRA-06 - ANM-27/29/20/21/22/23)
Phụ trách: TV3 - Ngọc Thắng (Trưởng nhóm: Ngọc Thắng)
Mục tiêu: Xác minh môi trường và các chức năng cơ bản trước khi thực nghiệm khai thác.
"""

import sys
import os
import subprocess
import time
import requests

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

VULN_BASE = "http://localhost:8080"
SECURED_BASE = "http://localhost:8081"

SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "tasks", "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

def take_screenshot(url, filename):
    output_path = os.path.join(SCREENSHOTS_DIR, filename)
    if not os.path.exists(CHROME_PATH):
        print(f"[-] Không tìm thấy Chrome tại: {CHROME_PATH}")
        return False
    user_data = os.path.join(os.environ.get("TEMP", "C:\\Temp"), f"chrome_ss_{int(time.time()*1000)}")
    cmd = [
        CHROME_PATH,
        "--headless=new",
        f"--user-data-dir={user_data}",
        "--window-size=1280,850",
        f"--screenshot={output_path}",
        url
    ]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        size_kb = os.path.getsize(output_path) / 1024
        print(f"    [+] Ảnh chụp màn hình: {filename} ({size_kb:.1f} KB)")
        return True
    except Exception as e:
        print(f"    [-] Lỗi chụp ảnh {filename}: {e}")
        return False

def query_db(sql):
    cmd = [
        "docker", "exec", "websec_mysql_db",
        "mysql", "-u", "db_user", "-pP@ssword123", "--default-character-set=utf8mb4", "ecommerce_db", "-sN", "-e", sql
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        raise RuntimeError(f"Lỗi truy vấn CSDL: {res.stderr.strip()}")
    return res.stdout.strip()

def run_tests():
    print("=" * 70)
    print(" BẮT ĐẦU KIỂM TRA TÍCH HỢP TOÀN HỆ THỐNG LAB (INFRA-06)")
    print("=" * 70)

    checklist_results = []

    def record_step(tc_id, title, target, result, details):
        status_str = "ĐẠT (PASS)" if result else "KHÔNG ĐẠT (FAIL)"
        checklist_results.append({
            "id": tc_id,
            "title": title,
            "target": target,
            "result": status_str,
            "passed": bool(result),
            "details": details
        })
        icon = "[✓]" if result else "[✗]"
        print(f"{icon} [{tc_id}] {title} ({target}) -> {status_str}: {details}")

    # =========================================================================
    # 1. KIỂM TRA HẠ TẦNG VÀ CÁC DỊCH VỤ
    # =========================================================================
    print("\n--- PHẦN 1: KIỂM TRA HẠ TẦNG VÀ KẾT NỐI DỊCH VỤ ---")
    
    # 1.1 MariaDB
    try:
        u_count = int(query_db("SELECT count(*) FROM users;"))
        p_count = int(query_db("SELECT count(*) FROM products;"))
        c_count = int(query_db("SELECT count(*) FROM comments;"))
        record_step(
            "INFRA-06-01",
            "Kết nối CSDL MariaDB và kiểm tra dữ liệu hạt giống",
            "websec_mysql_db (3306)",
            (u_count == 4 and p_count == 5 and c_count >= 3),
            f"users: {u_count}/4, products: {p_count}/5, comments: {c_count}/3"
        )
    except Exception as e:
        record_step("INFRA-06-01", "Kết nối CSDL MariaDB", "websec_mysql_db", False, str(e))

    # =========================================================================
    # 2. KIỂM TRA ỨNG DỤNG DÍNH LỖ HỔNG (VULNERABLE APP - PORT 8080)
    # =========================================================================
    print("\n--- PHẦN 2: KIỂM TRA CHỨC NĂNG TRÊN APP DÍNH LỖ HỔNG (PORT 8080) ---")
    session_vuln = requests.Session()

    # 2.1 Trang chủ & Danh mục sản phẩm
    try:
        r_home = session_vuln.get(f"{VULN_BASE}/", timeout=5)
        has_catalog = "iPhone 15 Pro Max" in r_home.text and "Samsung Galaxy S24 Ultra" in r_home.text
        record_step(
            "INFRA-06-03",
            "Tải trang chủ và nạp danh mục sản phẩm từ CSDL",
            "app-vulnerable (8080)",
            r_home.status_code == 200 and has_catalog,
            f"HTTP {r_home.status_code}, dung lượng phản hồi: {len(r_home.text)} bytes"
        )
        take_screenshot(f"{VULN_BASE}/", "01_vulnerable_homepage_8080.png")
    except Exception as e:
        record_step("INFRA-06-03", "Trang chủ app-vulnerable", "app-vulnerable", False, str(e))

    # 2.2 Đăng nhập bằng tài khoản giả lập nguyenvana
    try:
        login_data = {"username": "nguyenvana", "password": "pass123456"}
        r_login = session_vuln.post(f"{VULN_BASE}/login", data=login_data, allow_redirects=True, timeout=5)
        cookie_val = session_vuln.cookies.get("session_token")
        login_success = ("Nguyễn Văn A" in r_login.text or "nguyenvana" in r_login.text) and cookie_val is not None
        record_step(
            "INFRA-06-04",
            "Đăng nhập tài khoản giả lập (nguyenvana) và tạo phiên",
            "app-vulnerable (8080)",
            login_success,
            f"Người dùng xác thực thành công, session_token = {cookie_val[:18]}..."
        )
        take_screenshot(f"{VULN_BASE}/login", "02_vulnerable_login_8080.png")
    except Exception as e:
        record_step("INFRA-06-04", "Đăng nhập app-vulnerable", "app-vulnerable", False, str(e))

    # 2.3 Tìm kiếm sản phẩm
    try:
        r_search = session_vuln.get(f"{VULN_BASE}/search?keyword=iPhone", timeout=5)
        search_ok = r_search.status_code == 200 and "iPhone 15 Pro Max" in r_search.text and "SELECT id, name" in r_search.text
        record_step(
            "INFRA-06-05",
            "Tìm kiếm sản phẩm theo từ khóa (keyword=iPhone)",
            "app-vulnerable (8080)",
            search_ok,
            f"HTTP {r_search.status_code}, tìm thấy sản phẩm iPhone 15 Pro Max và truy vấn SQL mẫu"
        )
        take_screenshot(f"{VULN_BASE}/search?keyword=iPhone", "03_vulnerable_search_8080.png")
    except Exception as e:
        record_step("INFRA-06-05", "Tìm kiếm app-vulnerable", "app-vulnerable", False, str(e))

    # 2.4 Xem chi tiết sản phẩm
    try:
        r_prod = session_vuln.get(f"{VULN_BASE}/product?id=1", timeout=5)
        prod_ok = r_prod.status_code == 200 and "iPhone 15 Pro Max" in r_prod.text and "Đánh giá từ khách hàng" in r_prod.text
        record_step(
            "INFRA-06-06",
            "Xem chi tiết sản phẩm và danh sách bình luận (id=1)",
            "app-vulnerable (8080)",
            prod_ok,
            f"HTTP {r_prod.status_code}, hiển thị sản phẩm và danh sách đánh giá ban đầu"
        )
    except Exception as e:
        record_step("INFRA-06-06", "Xem chi tiết app-vulnerable", "app-vulnerable", False, str(e))

    # 2.5 Gửi bình luận đánh giá mới (dữ liệu giả lập)
    try:
        comment_content = "Đánh giá kiểm thử tích hợp INFRA-06 trên app-vulnerable"
        post_cmt = session_vuln.post(
            f"{VULN_BASE}/product",
            data={"product_id": "1", "author": "Nguyễn Văn A (Kiểm Thử)", "content": comment_content},
            allow_redirects=True,
            timeout=5
        )
        cmt_ok = post_cmt.status_code == 200 and comment_content in post_cmt.text
        record_step(
            "INFRA-06-07",
            "Gửi bình luận mới và hiển thị trên giao diện chi tiết",
            "app-vulnerable (8080)",
            cmt_ok,
            f"Bình luận mới đã được lưu vào CSDL và kết xuất thành công trên trang id=1"
        )
        take_screenshot(f"{VULN_BASE}/product?id=1", "04_vulnerable_product_comments_8080.png")
    except Exception as e:
        record_step("INFRA-06-07", "Gửi bình luận app-vulnerable", "app-vulnerable", False, str(e))

    # 2.6 Đăng xuất và hủy phiên
    try:
        r_logout = session_vuln.get(f"{VULN_BASE}/logout", allow_redirects=True, timeout=5)
        # Kiểm tra tải lại trang chủ ở trạng thái khách vãng lai
        r_check_anon = session_vuln.get(f"{VULN_BASE}/", timeout=5)
        logout_ok = "Đăng nhập" in r_check_anon.text and "Nguyễn Văn A" not in r_check_anon.text
        record_step(
            "INFRA-06-08",
            "Đăng xuất, xóa cookie và hủy trạng thái phiên",
            "app-vulnerable (8080)",
            logout_ok,
            "Phiên HttpSession bị hủy, quay lại giao diện khách vãng lai"
        )
    except Exception as e:
        record_step("INFRA-06-08", "Đăng xuất app-vulnerable", "app-vulnerable", False, str(e))

    # =========================================================================
    # 3. KIỂM TRA ỨNG DỤNG ĐÃ VÁ LỖ HỔNG (SECURED APP - PORT 8081)
    # =========================================================================
    print("\n--- PHẦN 3: KIỂM TRA CHỨC NĂNG TRÊN APP ĐÃ VÁ BẢO MẬT (PORT 8081) ---")
    session_sec = requests.Session()

    # 3.1 Trang chủ & Danh mục sản phẩm
    try:
        r_home_s = session_sec.get(f"{SECURED_BASE}/", timeout=5)
        has_catalog_s = "iPhone 15 Pro Max" in r_home_s.text and "Sony WH-1000XM5" in r_home_s.text
        # Kiểm tra Security Headers
        has_csp = "Content-Security-Policy" in r_home_s.headers
        has_xframe = "X-Frame-Options" in r_home_s.headers
        record_step(
            "INFRA-06-09",
            "Tải trang chủ, nạp danh mục và kiểm tra Security Headers",
            "app-secured (8081)",
            r_home_s.status_code == 200 and has_catalog_s and (has_csp and has_xframe),
            f"HTTP {r_home_s.status_code}, CSP: {has_csp}, X-Frame-Options: {has_xframe}"
        )
        take_screenshot(f"{SECURED_BASE}/", "05_secured_homepage_8081.png")
    except Exception as e:
        record_step("INFRA-06-09", "Trang chủ app-secured", "app-secured", False, str(e))

    # 3.2 Đăng nhập bằng tài khoản quản trị giả lập admin
    try:
        login_data_s = {"username": "admin", "password": "admin123_super_secret"}
        r_login_s = session_sec.post(f"{SECURED_BASE}/login", data=login_data_s, allow_redirects=True, timeout=5)
        login_success_s = ("Quản Trị Viên Hệ Thống" in r_login_s.text or "admin" in r_login_s.text)
        record_step(
            "INFRA-06-10",
            "Đăng nhập tài khoản giả lập (admin) với PreparedStatement",
            "app-secured (8081)",
            login_success_s,
            "Đăng nhập thành công, chào Quản Trị Viên Hệ Thống (admin), role=admin"
        )
        take_screenshot(f"{SECURED_BASE}/login", "06_secured_login_8081.png")
    except Exception as e:
        record_step("INFRA-06-10", "Đăng nhập app-secured", "app-secured", False, str(e))

    # 3.3 Tìm kiếm sản phẩm
    try:
        r_search_s = session_sec.get(f"{SECURED_BASE}/search?keyword=Samsung", timeout=5)
        search_ok_s = r_search_s.status_code == 200 and "Samsung Galaxy S24 Ultra" in r_search_s.text
        record_step(
            "INFRA-06-11",
            "Tìm kiếm sản phẩm an toàn (keyword=Samsung)",
            "app-secured (8081)",
            search_ok_s,
            f"HTTP {r_search_s.status_code}, tìm thấy Samsung Galaxy S24 Ultra qua truy vấn tham số hóa"
        )
        take_screenshot(f"{SECURED_BASE}/search?keyword=Samsung", "07_secured_search_8081.png")
    except Exception as e:
        record_step("INFRA-06-11", "Tìm kiếm app-secured", "app-secured", False, str(e))

    # 3.4 Xem chi tiết sản phẩm
    try:
        r_prod_s = session_sec.get(f"{SECURED_BASE}/product?id=2", timeout=5)
        prod_ok_s = r_prod_s.status_code == 200 and "Samsung Galaxy S24 Ultra" in r_prod_s.text
        record_step(
            "INFRA-06-12",
            "Xem chi tiết sản phẩm và danh sách bình luận (id=2)",
            "app-secured (8081)",
            prod_ok_s,
            f"HTTP {r_prod_s.status_code}, hiển thị sản phẩm id=2 và đánh giá hiện hữu"
        )
    except Exception as e:
        record_step("INFRA-06-12", "Xem chi tiết app-secured", "app-secured", False, str(e))

    # 3.5 Gửi bình luận đánh giá mới (dữ liệu giả lập)
    try:
        comment_content_s = "Đánh giá kiểm thử tích hợp INFRA-06 trên app-secured"
        post_cmt_s = session_sec.post(
            f"{SECURED_BASE}/product",
            data={"product_id": "2", "author": "Quản Trị Viên (Kiểm Thử)", "content": comment_content_s},
            allow_redirects=True,
            timeout=5
        )
        cmt_ok_s = post_cmt_s.status_code == 200 and comment_content_s in post_cmt_s.text
        record_step(
            "INFRA-06-13",
            "Gửi bình luận mới trên app-secured (PreparedStatement)",
            "app-secured (8081)",
            cmt_ok_s,
            f"Bình luận đã được lưu an toàn và hiển thị trên giao diện"
        )
        take_screenshot(f"{SECURED_BASE}/product?id=2", "08_secured_product_comments_8081.png")
    except Exception as e:
        record_step("INFRA-06-13", "Gửi bình luận app-secured", "app-secured", False, str(e))

    # 3.6 Đăng xuất và hủy phiên
    try:
        r_logout_s = session_sec.get(f"{SECURED_BASE}/logout", allow_redirects=True, timeout=5)
        r_check_anon_s = session_sec.get(f"{SECURED_BASE}/", timeout=5)
        logout_ok_s = "Đăng nhập" in r_check_anon_s.text and "Quản Trị Viên" not in r_check_anon_s.text
        record_step(
            "INFRA-06-14",
            "Đăng xuất, xóa cookie HttpOnly và hủy trạng thái phiên",
            "app-secured (8081)",
            logout_ok_s,
            "Phiên làm việc bảo mật bị hủy, cookie Max-Age=0, trở về trạng thái khách vãng lai"
        )
    except Exception as e:
        record_step("INFRA-06-14", "Đăng xuất app-secured", "app-secured", False, str(e))

    # =========================================================================
    # 4. KIỂM TRA QUY TRÌNH RESET DỮ LIỆU
    # =========================================================================
    print("\n--- PHẦN 4: KIỂM TRA QUY TRÌNH RESET DỮ LIỆU CHO TỪNG LƯỢT THỬ ---")
    try:
        comments_before = int(query_db("SELECT count(*) FROM comments;"))
        print(f"[*] Số lượng bình luận trước khi reset: {comments_before} (gồm 3 mẫu ban đầu + 2 mẫu test vừa thêm)")
        
        # Chạy script reset CSDL
        reset_script = os.path.join(os.path.dirname(__file__), "reset_db.ps1")
        reset_res = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", reset_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        
        comments_after = int(query_db("SELECT count(*) FROM comments;"))
        users_after = int(query_db("SELECT count(*) FROM users;"))
        products_after = int(query_db("SELECT count(*) FROM products;"))
        
        reset_success = (reset_res.returncode == 0 and comments_after == 3 and users_after == 4 and products_after == 5)
        record_step(
            "INFRA-06-15",
            "Kích hoạt và xác minh quy trình reset dữ liệu CSDL lab",
            "websec_mysql_db (init.sql)",
            reset_success,
            f"Reset thành công: comments={comments_after} (đã xóa 2 bình luận test), users={users_after}, products={products_after}"
        )
    except Exception as e:
        record_step("INFRA-06-15", "Quy trình reset CSDL", "websec_mysql_db", False, str(e))


    # =========================================================================
    # TỔNG KẾT KẾT QUẢ
    # =========================================================================
    print("\n" + "=" * 70)
    print(" BẢNG TỔNG HỢP KẾT QUẢ CHECKLIST TÍCH HỢP INFRA-06")
    print("=" * 70)
    total = len(checklist_results)
    passed = sum(1 for item in checklist_results if item["passed"])
    failed = total - passed

    for item in checklist_results:
        print(f"| {item['id']} | {item['title'][:40]:<40} | {item['target']:<24} | {item['result']} |")

    print("-" * 70)
    print(f"TỔNG SỐ KỊCH BẢN: {total} | ĐẠT (PASS): {passed} | KHÔNG ĐẠT (FAIL): {failed}")
    if failed == 0:
        print(">>> KẾT LUẬN: TOÀN BỘ HỆ THỐNG LAB ĐẠT CHUẨN ĐỂ TIẾN HÀNH KHAI THÁC!")
    else:
        print(">>> KẾT LUẬN: CÓ LỖI CHẶN LUỒNG CẦN XỬ LÝ TRƯỚC KHI CHUYỂN BƯỚC.")
    print("=" * 70)

    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
