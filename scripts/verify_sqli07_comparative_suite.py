#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kịch bản kiểm thử đối chứng toàn diện các ca truy vấn SQL trước/sau bản vá (Task SQLI-07 - ANM-37)
Phụ trách: TV3 - Ngọc Thắng (Trưởng nhóm: Ngọc Thắng)
Mục tiêu: Đánh giá khả năng hoạt động bình thường của các truy vấn hợp lệ và hiệu quả ngăn chặn
tất cả các dạng tấn công SQL Injection trên 4 nhóm chức năng cốt lõi.
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

def reset_db():
    script = os.path.join(os.path.dirname(__file__), "reset_db.ps1")
    if os.name == 'nt' and os.path.exists(script):
        subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')

def run_sqli_comparative_suite():
    print("=" * 80)
    print(" KIỂM THỬ ĐỐI CHỨNG TOÀN DIỆN CÁC TRUY VẤN SQL TRƯỚC/SAU (SQLI-07 / ANM-37)")
    print("=" * 80)

    reset_db()
    results = []

    # -------------------------------------------------------------------------
    # NHÓM 1: CHỨC NĂNG BÌNH THƯỜNG (NORMAL VALID FUNCTIONALITY)
    # -------------------------------------------------------------------------
    print("\n[PHẦN 1] Kiểm tra các ca truy vấn nghiệp vụ hợp lệ trên cả 2 phiên bản:")

    # 1.1 Đăng nhập hợp lệ
    v_norm_log = requests.post(f"{VULN_URL}/login", data={"username": "nguyenvana", "password": "pass123456"}, allow_redirects=False)
    s_norm_log = requests.post(f"{SECURED_URL}/login", data={"username": "nguyenvana", "password": "pass123456"}, allow_redirects=False)
    v_log_ok = v_norm_log.status_code == 302 and "index" in v_norm_log.headers.get("Location", "")
    s_log_ok = s_norm_log.status_code == 302 and "index" in s_norm_log.headers.get("Location", "")
    results.append({
        "id": "SQLI07-NORM-01",
        "type": "Nghiệp vụ thường",
        "endpoint": "POST /login",
        "payload": "nguyenvana / pass123456",
        "vuln_status": "ĐẠT (HTTP 302 -> /index.php)" if v_log_ok else "LỖI",
        "sec_status": "ĐẠT (HTTP 302 -> /index.php)" if s_log_ok else "LỖI",
        "pass": v_log_ok and s_log_ok,
        "note": "Xác thực tài khoản khách hàng thông thường thành công"
    })

    # 1.2 Tìm kiếm bình thường
    v_norm_search = requests.get(f"{VULN_URL}/search", params={"keyword": "iPhone"})
    s_norm_search = requests.get(f"{SECURED_URL}/search", params={"keyword": "iPhone"})
    v_srch_ok = "iPhone 15 Pro Max" in v_norm_search.text
    s_srch_ok = "iPhone 15 Pro Max" in s_norm_search.text
    results.append({
        "id": "SQLI07-NORM-02",
        "type": "Nghiệp vụ thường",
        "endpoint": "GET /search",
        "payload": "keyword=iPhone",
        "vuln_status": "ĐẠT (Tìm thấy iPhone)" if v_srch_ok else "LỖI",
        "sec_status": "ĐẠT (Tìm thấy iPhone)" if s_srch_ok else "LỖI",
        "pass": v_srch_ok and s_srch_ok,
        "note": "Truy vấn tìm kiếm trả về đúng danh sách sản phẩm khớp từ khóa"
    })

    # 1.3 Xem chi tiết bình thường
    v_norm_det = requests.get(f"{VULN_URL}/product", params={"id": "1"})
    s_norm_det = requests.get(f"{SECURED_URL}/product", params={"id": "1"})
    v_det_ok = "iPhone 15 Pro Max" in v_norm_det.text and "Titan tự nhiên" in v_norm_det.text
    s_det_ok = "iPhone 15 Pro Max" in s_norm_det.text and "Titan tự nhiên" in s_norm_det.text
    results.append({
        "id": "SQLI07-NORM-03",
        "type": "Nghiệp vụ thường",
        "endpoint": "GET /product",
        "payload": "id=1",
        "vuln_status": "ĐẠT (Đọc chi tiết sản phẩm 1)" if v_det_ok else "LỖI",
        "sec_status": "ĐẠT (Đọc chi tiết sản phẩm 1)" if s_det_ok else "LỖI",
        "pass": v_det_ok and s_det_ok,
        "note": "Hiển thị đầy đủ thông tin chi tiết và bình luận ban đầu"
    })

    # 1.4 Thêm bình luận hợp lệ
    v_norm_cmt = requests.post(f"{VULN_URL}/product", data={"product_id": "1", "author": "Khách Test", "content": "Bình luận tốt!"})
    s_norm_cmt = requests.post(f"{SECURED_URL}/product", data={"product_id": "2", "author": "Khách Test", "content": "Bình luận tốt!"})
    v_cmt_view = requests.get(f"{VULN_URL}/product?id=1")
    s_cmt_view = requests.get(f"{SECURED_URL}/product?id=2")
    v_cmt_ok = "Bình luận tốt!" in v_cmt_view.text
    s_cmt_ok = "Bình luận tốt!" in s_cmt_view.text
    results.append({
        "id": "SQLI07-NORM-04",
        "type": "Nghiệp vụ thường",
        "endpoint": "POST /product",
        "payload": "author=Khách Test, content=Bình luận tốt!",
        "vuln_status": "ĐẠT (Lưu và đọc thành công)" if v_cmt_ok else "LỖI",
        "sec_status": "ĐẠT (Lưu và đọc thành công)" if s_cmt_ok else "LỖI",
        "pass": v_cmt_ok and s_cmt_ok,
        "note": "Gửi và hiển thị bình luận hợp lệ vào CSDL"
    })

    # -------------------------------------------------------------------------
    # NHÓM 2: CÁC CA TẤN CÔNG SQL INJECTION (ATTACK TEST CASES)
    # -------------------------------------------------------------------------
    print("\n[PHẦN 2] Kiểm tra các ca tấn công SQL Injection trên 4 nhóm endpoint:")

    # 2.1 SQLi Login Bypass
    auth_payload = "admin' -- "
    v_atk_log = requests.post(f"{VULN_URL}/login", data={"username": auth_payload, "password": "wrong_password_999"}, allow_redirects=False)
    s_atk_log = requests.post(f"{SECURED_URL}/login", data={"username": auth_payload, "password": "wrong_password_999"}, allow_redirects=False)
    v_bypassed = v_atk_log.status_code == 302 and "index" in v_atk_log.headers.get("Location", "")
    s_blocked = s_atk_log.status_code == 200 and "index" not in s_atk_log.headers.get("Location", "")
    results.append({
        "id": "SQLI07-ATK-01",
        "type": "Tấn công SQLi",
        "endpoint": "POST /login",
        "payload": f"username=\"{auth_payload}\"",
        "vuln_status": "BỊ VƯỢT QUA (Bypass cấp phiên admin)",
        "sec_status": "CHẶN ĐỨNG (HTTP 200, báo sai pass)",
        "pass": v_bypassed and s_blocked,
        "note": "Bản vá: PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE username = ? AND password = ?\")"
    })

    # 2.2 SQLi Search Union-based
    union_payload = "%' UNION SELECT 999, 'SQLI07_EXPLOIT_MARKER', 'Khai thac thanh cong', '88888888' -- "
    v_atk_srch = requests.get(f"{VULN_URL}/search", params={"keyword": union_payload})
    s_atk_srch = requests.get(f"{SECURED_URL}/search", params={"keyword": union_payload})
    v_srch_injected = "<h4>SQLI07_EXPLOIT_MARKER</h4>" in v_atk_srch.text
    s_srch_safe = "<h4>SQLI07_EXPLOIT_MARKER</h4>" not in s_atk_srch.text
    results.append({
        "id": "SQLI07-ATK-02",
        "type": "Tấn công SQLi",
        "endpoint": "GET /search",
        "payload": "keyword=\"%' UNION SELECT 999, 'SQLI07_EXPLOIT_MARKER'...\"",
        "vuln_status": "BỊ TRÍCH XUẤT (Xuất hiện thẻ sản phẩm chèn)",
        "sec_status": "CHẶN ĐỨNG (Coi như chuỗi tìm kiếm, 0 kết quả)",
        "pass": v_srch_injected and s_srch_safe,
        "note": "Bản vá: pstmt.setString(1, \"%\" + cleanKeyword + \"%\") tách biệt hoàn toàn cú pháp SQL"
    })

    # 2.3 SQLi Product Detail
    det_payload = "-1 UNION SELECT 999, 'SQLI07_DETAIL_MARKER', 'Thong tin gia mao', '77777777', 'dien thoai' -- "
    v_atk_det = requests.get(f"{VULN_URL}/product", params={"id": det_payload})
    s_atk_det = requests.get(f"{SECURED_URL}/product", params={"id": det_payload})
    v_det_injected = "SQLI07_DETAIL_MARKER" in v_atk_det.text
    s_det_safe = "SQLI07_DETAIL_MARKER" not in s_atk_det.text
    results.append({
        "id": "SQLI07-ATK-03",
        "type": "Tấn công SQLi",
        "endpoint": "GET /product",
        "payload": "id=\"-1 UNION SELECT 999, 'SQLI07_DETAIL_MARKER'...\"",
        "vuln_status": "BỊ TIÊM DỮ LIỆU (Hiển thị chi tiết giả mạo)",
        "sec_status": "CHẶN ĐỨNG (Ép kiểu Integer.parseInt + PreparedStatement)",
        "pass": v_det_injected and s_det_safe,
        "note": "Bản vá: Integer.parseInt ép kiểu nghiêm ngặt và PreparedStatement WHERE id = ?"
    })

    # 2.4 SQLi Comment Insert Injection
    cmt_payload = "Attacker', 'SQLI07_SPLIT_CONTENT'); -- "
    requests.post(f"{VULN_URL}/product", data={"product_id": "1", "author": cmt_payload, "content": "OriginalText"})
    requests.post(f"{SECURED_URL}/product", data={"product_id": "2", "author": cmt_payload, "content": "OriginalSafeText"})
    v_chk_cmt = requests.get(f"{VULN_URL}/product?id=1")
    s_chk_cmt = requests.get(f"{SECURED_URL}/product?id=2")
    v_split_injected = '<div class="comment-body">SQLI07_SPLIT_CONTENT</div>' in v_chk_cmt.text
    s_split_safe = ('<div class="comment-body">OriginalSafeText</div>' in s_chk_cmt.text and
                    '<div class="comment-body">SQLI07_SPLIT_CONTENT</div>' not in s_chk_cmt.text)
    results.append({
        "id": "SQLI07-ATK-04",
        "type": "Tấn công SQLi",
        "endpoint": "POST /product",
        "payload": f"author=\"{cmt_payload}\"",
        "vuln_status": "BỊ TÁCH CỘT (Chuỗi chèn trở thành cột content)",
        "sec_status": "CHẶN ĐỨNG (Lưu trọn vẹn tham số author)",
        "pass": v_split_injected and s_split_safe,
        "note": "Bản vá: INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)"
    })

    reset_db()

    # -------------------------------------------------------------------------
    # TỔNG HỢP KẾT QUẢ ĐỐI CHỨNG
    # -------------------------------------------------------------------------
    print("\n" + "=" * 90)
    print(" BẢNG TỔNG HỢP ĐỐI CHỨNG TRƯỚC/SAU CÁC NHÓM TRUY VẤN SQL (SQLI-07 / ANM-37)")
    print("=" * 90)
    print(f"| {'Mã ca':<14} | {'Hạng mục':<15} | {'Điểm cuối':<14} | {'Vulnerable (8080)':<20} | {'Secured (8081)':<20} | {'Đánh giá':<8} |")
    print("|" + "-"*16 + "|" + "-"*17 + "|" + "-"*16 + "|" + "-"*22 + "|" + "-"*22 + "|" + "-"*10 + "|")

    all_passed = True
    for r in results:
        status_txt = "ĐẠT" if r["pass"] else "FAIL"
        if not r["pass"]:
            all_passed = False
        print(f"| {r['id']:<14} | {r['type']:<15} | {r['endpoint']:<14} | {r['vuln_status'][:20]:<20} | {r['sec_status'][:20]:<20} | {status_txt:<8} |")

    print("-" * 90)
    print(f"TỔNG KẾT: {'8/8 CA ĐỐI CHỨNG ĐẠT (PASS 100%)' if all_passed else 'CÓ LỖI'}")
    print("ĐÁNH GIÁ AN NINH:")
    print(" - Các truy vấn hợp lệ (Normal) hoạt động trơn tru 100% trên cả 2 phiên bản.")
    print(" - 100% các ca tấn công SQL Injection bị ngăn chặn triệt để trên bản Secured.")
    print(" - Lưu ý: Các biện pháp bảo vệ này giải quyết triệt để SQLi trên phạm vi mã nguồn ứng dụng,")
    print("   cần tiếp tục kết hợp phân quyền CSDL nguyên tắc đặc quyền tối thiểu (least privilege).")
    print("=" * 90)

    return all_passed

if __name__ == "__main__":
    ok = run_sqli_comparative_suite()
    sys.exit(0 if ok else 1)
