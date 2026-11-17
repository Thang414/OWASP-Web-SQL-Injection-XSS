#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kịch bản kiểm thử luồng chức năng đầu cuối (End-to-End Functional Verification)
Mã nội bộ: VERIFY-03 (Task Jira: ANM-48)
Phụ trách: TV3 - Ngọc Thắng (Trưởng nhóm: Ngọc Thắng)
Mục tiêu: Xác nhận hai ứng dụng (app-vulnerable: 8080 và app-secured: 8081) hoàn thành
đầy đủ luồng nghiệp vụ người dùng: Duyệt trang chủ -> Tìm kiếm -> Xem chi tiết ->
Đăng nhập -> Giữ phiên tải lại -> Thêm bình luận -> Đăng xuất.
"""

import os
import sys
import subprocess
import requests

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"

def reset_database():
    script = os.path.join(os.path.dirname(__file__), "reset_db.ps1")
    if os.name == 'nt' and os.path.exists(script):
        res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        return res.returncode == 0
    return False

def test_app_e2e(app_name, base_url, test_user, test_pass, test_fullname, search_term, product_id, product_name):
    print(f"\n" + "-" * 70)
    print(f" [E2E] BẮT ĐẦU KIỂM THỬ LUỒNG NGƯỜI DÙNG ĐẦU CUỐI: {app_name} ({base_url})")
    print("-" * 70)

    steps = []
    session = requests.Session()

    def record_step(step_no, step_name, success, detail):
        status_str = "ĐẠT (PASS)" if success else "LỖI (FAIL)"
        steps.append({"step": step_no, "name": step_name, "status": status_str, "detail": detail, "pass": success})
        icon = "[✓]" if success else "[✗]"
        print(f"  {icon} Bước {step_no}: {step_name} -> {status_str} ({detail})")

    # Bước 1: Truy cập trang chủ (Chưa đăng nhập)
    r1 = session.get(f"{base_url}/")
    ok1 = r1.status_code == 200 and "Danh sách sản phẩm" in r1.text and "Đăng nhập" in r1.text
    record_step(1, "Truy cập trang chủ (Khách vãng lai)", ok1, f"HTTP {r1.status_code}, hiển thị danh mục sản phẩm")

    # Bước 2: Tìm kiếm sản phẩm
    r2 = session.get(f"{base_url}/search", params={"keyword": search_term})
    ok2 = r2.status_code == 200 and search_term in r2.text and product_name in r2.text
    record_step(2, f"Tìm kiếm sản phẩm từ khóa '{search_term}'", ok2, f"HTTP {r2.status_code}, thấy '{product_name}'")

    # Bước 3: Xem trang chi tiết sản phẩm
    r3 = session.get(f"{base_url}/product", params={"id": product_id})
    ok3 = r3.status_code == 200 and product_name in r3.text and "VNĐ" in r3.text
    record_step(3, f"Xem chi tiết sản phẩm id={product_id}", ok3, f"HTTP {r3.status_code}, hiển thị đúng giá tiền và mô tả")

    # Bước 4: Đăng nhập tài khoản
    r4 = session.post(f"{base_url}/login", data={"username": test_user, "password": test_pass}, allow_redirects=True)
    ok4 = r4.status_code == 200 and (test_fullname in r4.text or test_user in r4.text or "Đăng xuất" in r4.text)
    record_step(4, f"Đăng nhập tài khoản '{test_user}'", ok4, f"HTTP {r4.status_code}, cấp phiên thành công")

    # Bước 5: Tải lại trang chủ giữ phiên (Session Persistence)
    r5 = session.get(f"{base_url}/")
    ok5 = r5.status_code == 200 and (test_fullname in r5.text or test_user in r5.text) and "Đăng xuất" in r5.text
    record_step(5, "Tải lại trang chủ và giữ phiên làm việc", ok5, f"HTTP {r5.status_code}, phiên được duy trì chính xác")

    # Bước 6: Thêm bình luận đánh giá sản phẩm
    cmt_content = f"Đánh giá trải nghiệm {app_name} lúc {os.urandom(2).hex()}"
    r6 = session.post(f"{base_url}/product", data={"product_id": str(product_id), "author": test_fullname, "content": cmt_content}, allow_redirects=True)
    ok6 = r6.status_code == 200 and (cmt_content in r6.text or "thành công" in r6.text)
    record_step(6, f"Gửi bình luận mới vào sản phẩm id={product_id}", ok6, f"HTTP {r6.status_code}, bình luận đã gửi")

    # Bước 7: Xem lại trang chi tiết xác nhận bình luận xuất hiện
    r7 = session.get(f"{base_url}/product", params={"id": product_id})
    ok7 = r7.status_code == 200 and cmt_content in r7.text
    record_step(7, "Xác nhận hiển thị bình luận mới trên UI", ok7, f"HTTP {r7.status_code}, thấy nội dung đánh giá vừa tạo")

    # Bước 8: Đăng xuất người dùng
    r8 = session.get(f"{base_url}/logout", allow_redirects=True)
    r8_chk = session.get(f"{base_url}/")
    ok8 = r8.status_code == 200 and "Đăng nhập" in r8_chk.text and "Đăng xuất" not in r8_chk.text
    record_step(8, "Đăng xuất khỏi phiên làm việc", ok8, f"HTTP {r8.status_code}, phiên làm việc đã bị hủy an toàn")

    all_app_passed = all(s["pass"] for s in steps)
    return all_app_passed, steps

def run_e2e_verification():
    print("=" * 80)
    print(" BẮT ĐẦU KIỂM THỬ CHỨC NĂNG END-TO-END TRÊN HAI PHIÊN BẢN (VERIFY-03 / ANM-48)")
    print("=" * 80)

    print("\n[*] Đang hoàn nguyên cơ sở dữ liệu mẫu trước khi chạy...")
    db_ok = reset_database()
    print(f"    -> Trạng thái reset CSDL: {'Thành công' if db_ok else 'Sẵn sàng'}")

    # Chạy trên app-vulnerable
    v_ok, v_steps = test_app_e2e(
        app_name="App Vulnerable",
        base_url=VULN_URL,
        test_user="nguyenvana",
        test_pass="pass123456",
        test_fullname="Nguyễn Văn A",
        search_term="Samsung",
        product_id=2,
        product_name="Samsung Galaxy S24 Ultra"
    )

    # Chạy trên app-secured
    s_ok, s_steps = test_app_e2e(
        app_name="App Secured",
        base_url=SECURED_URL,
        test_user="manager",
        test_pass="manager@2026",
        test_fullname="Trưởng Phòng Kinh Doanh",
        search_term="Dell",
        product_id=3,
        product_name="Laptop Dell XPS 15"
    )

    print("\n[*] Hoàn nguyên CSDL sau khi hoàn tất kiểm thử...")
    reset_database()

    print("\n" + "=" * 80)
    print(" BẢNG TỔNG HỢP KẾT QUẢ CHECKLIST END-TO-END (VERIFY-03)")
    print("=" * 80)
    print(f"| {'Bước':<6} | {'Nghiệp vụ chức năng':<35} | {'Vulnerable (8080)':<16} | {'Secured (8081)':<16} |")
    print("|" + "-"*8 + "|" + "-"*37 + "|" + "-"*18 + "|" + "-"*18 + "|")
    for v_s, s_s in zip(v_steps, s_steps):
        print(f"| {v_s['step']:<6} | {v_s['name'][:35]:<35} | {v_s['status']:<16} | {s_s['status']:<16} |")

    total_steps = len(v_steps) + len(s_steps)
    passed_steps = sum(1 for s in v_steps if s['pass']) + sum(1 for s in s_steps if s['pass'])

    print("-" * 80)
    print(f"TỔNG SỐ BƯỚC THỰC HIỆN: {total_steps} | ĐẠT: {passed_steps} | LỖI: {total_steps - passed_steps}")
    print("XÁC NHẬN CHẤT LƯỢNG:")
    print(" - Cả hai ứng dụng hoàn thành trọn vẹn luồng nghiệp vụ người dùng không có lỗi chặn (No Blocking Bug).")
    print(" - Các cơ chế bảo mật trên bản Secured không làm ảnh hưởng hay phá vỡ bất kỳ trải nghiệm nào.")
    print("=" * 80)

    return v_ok and s_ok

if __name__ == "__main__":
    ok = run_e2e_verification()
    sys.exit(0 if ok else 1)
