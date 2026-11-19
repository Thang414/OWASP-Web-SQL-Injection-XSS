#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bộ kiểm thử hồi quy SQL Injection toàn diện (SQLI-02..06 / VERIFY-01 — ANM-32..36, ANM-46)
Chạy đối chứng trực tiếp trên app-vulnerable (:8080) và app-secured (:8081) với dữ liệu giả lập,
bao phủ: đăng nhập, tìm kiếm, chi tiết sản phẩm, đọc và thêm bình luận (thường, sai định dạng, SQLi).
"""

import os
import subprocess
import sys
import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"


def reset_db():
    script = os.path.join(os.path.dirname(__file__), "reset_db.ps1")
    if os.name == "nt" and os.path.exists(script):
        res = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        return res.returncode == 0
    return False


def run_sqli_regression():
    print("=" * 85)
    print(" KIỂM THỬ HỒI QUY SQL INJECTION ĐẦY ĐỦ (SQLI-02..06 / VERIFY-01 / ANM-32..36, ANM-46)")
    print("=" * 85)

    assert reset_db(), "Không thể reset CSDL lab trước khi chạy kiểm thử!"
    cases = []

    def record(cid, area, ok, detail):
        cases.append((cid, area, ok, detail))
        print(f"{'[✓]' if ok else '[✗]'} [{cid}] {area}: {'PASS' if ok else 'FAIL'} — {detail}")

    # 1. Đăng nhập hợp lệ & sai mật khẩu
    v_ok = requests.post(f"{VULN_URL}/login", data={"username": "nguyenvana", "password": "pass123456"}, allow_redirects=False, timeout=5)
    s_ok = requests.post(f"{SECURED_URL}/login", data={"username": "nguyenvana", "password": "pass123456"}, allow_redirects=False, timeout=5)
    s_bad = requests.post(f"{SECURED_URL}/login", data={"username": "nguyenvana", "password": "wrong"}, allow_redirects=False, timeout=5)
    record("SQLI-REG-01", "Login hợp lệ & sai mật khẩu",
           v_ok.status_code == 302 and s_ok.status_code == 302 and s_bad.status_code == 200,
           f"vuln_valid={v_ok.status_code}, sec_valid={s_ok.status_code}, sec_invalid={s_bad.status_code}")

    # 2. Login SQLi Auth Bypass (nhiều biến thể)
    auth_payloads = [
        ("admin' -- ", "wrong"),
        ("' OR 1=1 -- ", "wrong"),
        ("admin' or '1'='1", "' or '1'='1"),
    ]
    all_auth_ok = True
    for u, p in auth_payloads:
        rv = requests.post(f"{VULN_URL}/login", data={"username": u, "password": p}, allow_redirects=False, timeout=5)
        rs = requests.post(f"{SECURED_URL}/login", data={"username": u, "password": p}, allow_redirects=False, timeout=5)
        if not (rv.status_code == 302 and rs.status_code == 200 and "không chính xác" in rs.text):
            all_auth_ok = False
    record("SQLI-REG-02", "Login Auth Bypass (3 payload SQLi)", all_auth_ok,
           "Vulnerable bị vượt xác thực (302), Secured chặn 100% (200 + lỗi)")

    # 3. Search bình thường (tìm thấy, không tìm thấy, rỗng)
    s_found = requests.get(f"{SECURED_URL}/search", params={"keyword": "iPhone"}, timeout=5)
    s_miss = requests.get(f"{SECURED_URL}/search", params={"keyword": "KhongCoSanPhamNay"}, timeout=5)
    s_blank = requests.get(f"{SECURED_URL}/search", params={"keyword": "   "}, timeout=5)
    record("SQLI-REG-03", "Search hợp lệ (tìm thấy / không thấy / rỗng)",
           ("iPhone 15 Pro Max" in s_found.text and "Không tìm thấy sản phẩm" in s_miss.text and "MacBook Air M2" in s_blank.text),
           "Đủ 3 trường hợp tìm kiếm bình thường trên Secured")

    # 4. Search UNION SQLi với marker giả
    union_kw = "%' UNION SELECT 999, 'VERIFY01_UNION_MARKER', 'Mo ta danh dau', '10000' -- "
    rv_srch = requests.get(f"{VULN_URL}/search", params={"keyword": union_kw}, timeout=5)
    rs_srch = requests.get(f"{SECURED_URL}/search", params={"keyword": union_kw}, timeout=5)
    record("SQLI-REG-04", "Search UNION SELECT với marker giả",
           ("<h4>VERIFY01_UNION_MARKER</h4>" in rv_srch.text and
            "<h4>VERIFY01_UNION_MARKER</h4>" not in rs_srch.text and
            "Không tìm thấy sản phẩm" in rs_srch.text),
           "Vulnerable chèn thẻ sản phẩm giả; Secured trả 0 kết quả an toàn")

    # 5. Product Detail: hợp lệ, sai định dạng, không tồn tại, UNION SQLi
    det_sqli = "-1 UNION SELECT 999, 'VERIFY01_DETAIL_MARKER', 'Mo ta gia', 50000, 'Lab' -- "
    rv_det = requests.get(f"{VULN_URL}/product", params={"id": det_sqli}, timeout=5)
    rs_det = requests.get(f"{SECURED_URL}/product", params={"id": det_sqli}, timeout=5)
    rs_bad = requests.get(f"{SECURED_URL}/product", params={"id": "abc"}, timeout=5)
    rs_neg = requests.get(f"{SECURED_URL}/product", params={"id": "-10"}, timeout=5)
    rs_404 = requests.get(f"{SECURED_URL}/product", params={"id": "999"}, timeout=5)
    det_ok = (
        "<h2>VERIFY01_DETAIL_MARKER</h2>" in rv_det.text
        and "<h2>VERIFY01_DETAIL_MARKER</h2>" not in rs_det.text
        and "Sản phẩm không tồn tại" in rs_det.text
        and "Sản phẩm không tồn tại" in rs_bad.text
        and "Sản phẩm không tồn tại" in rs_neg.text
        and "Sản phẩm không tồn tại" in rs_404.text
        and "<h2>iPhone 15 Pro Max</h2>" not in rs_bad.text
    )
    record("SQLI-REG-05", "Product Detail UNION SQLi & ID sai định dạng (không fallback)", det_ok,
           "Vulnerable hiển thị marker giả; Secured từ chối rõ ràng không rơi sang SP khác")

    # 6. Add Comment: bình luận hợp lệ có dấu nháy đơn + chặn lỗi DB không tồn tại + tiêm product_id
    quote_resp = requests.post(
        f"{SECURED_URL}/product",
        data={"product_id": "1", "author": "O'Brien", "content": "Rất 'hài lòng' với máy!"},
        allow_redirects=True, timeout=5
    )
    bad_prod_resp = requests.post(
        f"{SECURED_URL}/product",
        data={"product_id": "999", "author": "Tester", "content": "Bình luận cho SP không tồn tại"},
        allow_redirects=True, timeout=5
    )
    ins_payload = "1, 'VERIFY01_SQLI_AUTHOR', 'VERIFY01_SQLI_ROW'), (1"
    requests.post(f"{VULN_URL}/product", data={"product_id": ins_payload, "author": "Normal", "content": "Orig"}, allow_redirects=True, timeout=5)
    v_after = requests.get(f"{VULN_URL}/product?id=1", timeout=5)
    s_ins_atk = requests.post(f"{SECURED_URL}/product", data={"product_id": ins_payload, "author": "Normal", "content": "Orig"}, allow_redirects=True, timeout=5)
    s_crlf_atk = requests.post(f"{SECURED_URL}/product", data={"product_id": "1\r\nX-Test: 1", "author": "Normal", "content": "Orig"}, allow_redirects=False, timeout=5)

    cmt_ok = (
        "Gửi bình luận đánh giá thành công!" in quote_resp.text
        and "Rất &#39;hài lòng&#39; với máy!" in quote_resp.text
        and "Không thể lưu bình luận" in bad_prod_resp.text
        and "VERIFY01_SQLI_ROW" in v_after.text
        and "Mã sản phẩm không hợp lệ!" in s_ins_atk.text
        and s_crlf_atk.status_code == 302
        and "\r" not in s_crlf_atk.headers.get("Location", "")
        and "\n" not in s_crlf_atk.headers.get("Location", "")
    )
    record("SQLI-REG-06", "Add Comment (nháy đơn, FK lỗi, tiêm product_id, CRLF redirect)", cmt_ok,
           "Vulnerable chèn thêm bản ghi giả; Secured lưu đúng nháy đơn & chặn tiêm an toàn")

    reset_db()

    passed = sum(1 for _, _, ok, _ in cases if ok)
    total = len(cases)
    print("-" * 85)
    print(f"TỔNG KẾT SQLI REGRESSION (VERIFY-01): {passed}/{total} ĐẠT")
    print("=" * 85)
    return passed == total


if __name__ == "__main__":
    sys.exit(0 if run_sqli_regression() else 1)
