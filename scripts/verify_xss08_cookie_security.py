#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kịch bản kiểm thử bảo mật cookie phiên xác thực (Task XSS-08 - ANM-45)
Phụ trách: TV3 - Ngọc Thắng (Trưởng nhóm: Ngọc Thắng)
Mục tiêu: Đánh giá thuộc tính HttpOnly, SameSite, Secure và vòng đời phiên (tạo, duy trì, hủy)
trên cả hai phiên bản app-vulnerable (8080) và app-secured (8081).
"""

import sys
import requests

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"

def parse_set_cookie_headers(response):
    cookies = {}
    for k, v in response.raw.headers.items():
        if k.lower() == 'set-cookie':
            parts = [p.strip() for p in v.split(';')]
            name_val = parts[0]
            if '=' in name_val:
                cname, cval = name_val.split('=', 1)
                flags = [p.lower() for p in parts[1:]]
                cookies[cname] = {
                    "value": cval,
                    "raw": v,
                    "httponly": any(f == 'httponly' for f in flags),
                    "samesite": next((p.split('=')[1] for p in parts if p.lower().startswith('samesite=')), None),
                    "secure": any(f == 'secure' for f in flags),
                    "path": next((p.split('=')[1] for p in parts if p.lower().startswith('path=')), None),
                    "max_age": next((p.split('=')[1] for p in parts if p.lower().startswith('max-age=')), None),
                }
    return cookies

def run_cookie_security_tests():
    print("=" * 80)
    print(" BẮT ĐẦU KIỂM THỬ THUỘC TÍNH COOKIE PHIÊN VÀ VÒNG ĐỜI PHIÊN (XSS-08 / ANM-45)")
    print("=" * 80)

    results = []

    # 1. Kiểm tra thuộc tính cookie khi đăng nhập
    print("\n[+] 1. Đăng nhập và thu thập Set-Cookie:")
    v_s = requests.Session()
    v_login = v_s.post(f"{VULN_URL}/login", data={"username": "admin", "password": "admin123_super_secret"}, allow_redirects=False)
    v_cookies = parse_set_cookie_headers(v_login)

    s_s = requests.Session()
    s_login = s_s.post(f"{SECURED_URL}/login", data={"username": "admin", "password": "admin123_super_secret"}, allow_redirects=False)
    s_cookies = parse_set_cookie_headers(s_login)

    print("    - Vulnerable Set-Cookie:", list(v_cookies.keys()))
    print("    - Secured Set-Cookie:   ", list(s_cookies.keys()))

    # Kiểm tra session_token trên vulnerable
    v_token = v_cookies.get("session_token", {})
    v_token_insecure = not v_token.get("httponly", False)
    print(f"    [Vulnerable] session_token HttpOnly: {v_token.get('httponly')} (Dễ bị đọc qua JavaScript: {v_token_insecure})")

    # Kiểm tra session_token trên secured
    s_token = s_cookies.get("session_token", {})
    s_token_secure = s_token.get("httponly", False) and s_token.get("samesite") == "Strict"
    print(f"    [Secured]    session_token HttpOnly: {s_token.get('httponly')}, SameSite: {s_token.get('samesite')} (An toàn: {s_token_secure})")

    results.append({
        "id": "XSS08-TC01",
        "desc": "Cấu hình thuộc tính HttpOnly và SameSite cho cookie phiên",
        "vuln": f"HttpOnly={v_token.get('httponly')}, SameSite={v_token.get('samesite')} (Lỗ hổng rò rỉ cookie qua XSS)",
        "sec": f"HttpOnly={s_token.get('httponly')}, SameSite={s_token.get('samesite')} (Chặn hoàn toàn JS truy cập và CSRF)",
        "pass": v_token_insecure and s_token_secure
    })

    # 2. Kiểm tra duy trì phiên làm việc (Session Persistence)
    print("\n[+] 2. Kiểm tra duy trì phiên làm việc sau đăng nhập:")
    v_home = v_s.get(f"{VULN_URL}/")
    s_home = s_s.get(f"{SECURED_URL}/")

    v_has_user = "Quản Trị Viên" in v_home.text or "admin" in v_home.text or "Đăng xuất" in v_home.text
    s_has_user = "Quản Trị Viên" in s_home.text or "admin" in s_home.text or "Đăng xuất" in s_home.text

    print(f"    - Vulnerable duy trì phiên: {v_has_user}")
    print(f"    - Secured duy trì phiên:    {s_has_user}")

    results.append({
        "id": "XSS08-TC02",
        "desc": "Duy trì phiên xác thực người dùng khi duyệt ứng dụng",
        "vuln": f"Duy trì phiên thành công (Hiển thị thông tin phiên user)",
        "sec": f"Duy trì phiên thành công (Hiển thị thông tin phiên user)",
        "pass": v_has_user and s_has_user
    })

    # 3. Kiểm tra đăng xuất và vô hiệu hóa phiên (Session Invalidation)
    print("\n[+] 3. Kiểm tra đăng xuất và vô hiệu hóa phiên:")
    v_logout = v_s.get(f"{VULN_URL}/logout", allow_redirects=True)
    s_logout = s_s.get(f"{SECURED_URL}/logout", allow_redirects=True)

    v_after_home = v_s.get(f"{VULN_URL}/")
    s_after_home = s_s.get(f"{SECURED_URL}/")

    v_logged_out = "Đăng nhập" in v_after_home.text and "Đăng xuất" not in v_after_home.text
    s_logged_out = "Đăng nhập" in s_after_home.text and "Đăng xuất" not in s_after_home.text

    print(f"    - Vulnerable hủy phiên: {v_logged_out}")
    print(f"    - Secured hủy phiên:    {s_logged_out}")

    results.append({
        "id": "XSS08-TC03",
        "desc": "Vô hiệu hóa phiên đăng nhập khi gọi /logout",
        "vuln": f"Phiên bị hủy thành công (Hết phiên làm việc)",
        "sec": f"Phiên bị hủy thành công (Hết phiên làm việc, xóa session)",
        "pass": v_logged_out and s_logged_out
    })

    # 4. Mô phỏng rủi ro đọc cookie qua JavaScript (XSS Cookie Stealing Simulation)
    print("\n[+] 4. Mô phỏng khả năng đánh cắp cookie qua document.cookie (XSS):")
    # Mô phỏng: Trình duyệt chỉ cho phép JS đọc các cookie KHÔNG có cờ HttpOnly
    js_accessible_v = [name for name, c in v_cookies.items() if not c.get("httponly", False)]
    js_accessible_s = [name for name, c in s_cookies.items() if not c.get("httponly", False)]

    print(f"    - Vulnerable cookies readable by JS: {js_accessible_v} -> Kẻ tấn công cướp được session_token!")
    print(f"    - Secured cookies readable by JS:    {js_accessible_s} -> Kẻ tấn công KHÔNG đọc được cookie phiên!")

    results.append({
        "id": "XSS08-TC04",
        "desc": "Mô phỏng rủi ro truy cập cookie qua document.cookie khi bị XSS",
        "vuln": f"JavaScript đọc được: {js_accessible_v} (Nguy cơ chiếm đoạt tài khoản)",
        "sec": f"JavaScript đọc được: {js_accessible_s} (Bảo vệ an toàn dữ liệu phiên)",
        "pass": ("session_token" in js_accessible_v) and ("session_token" not in js_accessible_s)
    })

    print("\n" + "=" * 80)
    print(" BẢNG TỔNG KẾT KẾT QUẢ KIỂM THỬ XSS-08 (ANM-45)")
    print("=" * 80)
    all_passed = True
    for r in results:
        status_str = "ĐẠT (PASS)" if r["pass"] else "KHÔNG ĐẠT (FAIL)"
        if not r["pass"]:
            all_passed = False
        print(f"[{status_str}] {r['id']} - {r['desc']}")
        print(f"   + Vulnerable: {r['vuln']}")
        print(f"   + Secured:    {r['sec']}")

    print("-" * 80)
    print(f"KẾT LUẬN: {'TẤT CẢ 4/4 CA KIỂM THỬ ĐẠT (PASS 100%)' if all_passed else 'CÓ LỖI XẢY RA'}")
    print("=" * 80)

    return all_passed

if __name__ == "__main__":
    ok = run_cookie_security_tests()
    sys.exit(0 if ok else 1)
