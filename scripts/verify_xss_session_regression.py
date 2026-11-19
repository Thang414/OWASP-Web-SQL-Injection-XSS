#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bộ kiểm thử hồi quy XSS, kiểm tra đầu vào, Security Headers, Cookie phiên & thực thi JS trên trình duyệt thật
Bao phủ: XSS-02..08 (ANM-39..45) và VERIFY-02 (ANM-47).
Chỉ dùng payload minh họa vô hại (thay đổi phần tử DOM cục bộ), không đọc/gửi cookie ra ngoài.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"
CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]


def find_browser():
    for p in CHROME_CANDIDATES:
        if os.path.exists(p):
            return p
    return shutil.which("chromium") or shutil.which("google-chrome")


def dump_dom(browser_path, url):
    user_data = tempfile.mkdtemp(prefix="websec_xss_dom_")
    try:
        res = subprocess.run(
            [
                browser_path,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                f"--user-data-dir={user_data}",
                "--dump-dom",
                url,
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        )
        return res.returncode, res.stdout, res.stderr
    finally:
        shutil.rmtree(user_data, ignore_errors=True)


def reset_db():
    script = os.path.join(os.path.dirname(__file__), "reset_db.ps1")
    if os.name == "nt" and os.path.exists(script):
        res = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        return res.returncode == 0
    return False


def get_set_cookies(resp):
    cookies = {}
    for k, v in resp.raw.headers.items():
        if k.lower() == "set-cookie":
            parts = [p.strip() for p in v.split(";")]
            if "=" in parts[0]:
                name, val = parts[0].split("=", 1)
                flags = [p.lower() for p in parts[1:]]
                cookies[name] = {
                    "value": val,
                    "raw": v,
                    "httponly": any(f == "httponly" for f in flags),
                    "secure": any(f == "secure" for f in flags),
                    "samesite": next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), None),
                }
    return cookies


def run_xss_session_regression():
    print("=" * 88)
    print(" KIỂM THỬ HỒI QUY XSS, VALIDATION, HEADERS, PHIÊN & BROWSER DOM (VERIFY-02 / ANM-39..47)")
    print("=" * 88)

    assert reset_db(), "Không thể reset CSDL lab!"
    browser = find_browser()
    cases = []

    def record(cid, name, ok, detail):
        cases.append((cid, name, ok, detail))
        print(f"{'[✓]' if ok else '[✗]'} [{cid}] {name}: {'PASS' if ok else 'FAIL'} — {detail}")

    # 1. XSS-03 / XSS-05: Reflected XSS với payload vô hại (DOM mutation) + đối chứng từ khóa thường
    rxss_payload = '<span id="rxss-box">INIT</span><script>document.getElementById("rxss-box").textContent="RXSS_DOM_OK"</script>'
    rv = requests.get(f"{VULN_URL}/search", params={"keyword": rxss_payload}, timeout=5)
    rs = requests.get(f"{SECURED_URL}/search", params={"keyword": rxss_payload}, timeout=5)
    rs_norm = requests.get(f"{SECURED_URL}/search", params={"keyword": "iPhone"}, timeout=5)

    rxss_http_ok = (
        rxss_payload in rv.text
        and rxss_payload not in rs.text
        and "&lt;script&gt;" in rs.text
        and "iPhone 15 Pro Max" in rs_norm.text
    )
    record("XSS-REG-01", "Reflected XSS HTTP response (raw trên Vuln, encoded trên Secured)", rxss_http_ok,
           "th:utext phản chiếu thô; th:text mã hóa &lt;script&gt;; tìm kiếm thường OK")

    # 2. Real Headless Browser DOM Execution cho Reflected XSS
    if browser:
        q = urllib.parse.urlencode({"keyword": rxss_payload})
        _, v_dom, _ = dump_dom(browser, f"{VULN_URL}/search?{q}")
        _, s_dom, _ = dump_dom(browser, f"{SECURED_URL}/search?{q}")
        v_exec = '<span id="rxss-box">RXSS_DOM_OK</span>' in v_dom
        s_not_exec = '<span id="rxss-box">RXSS_DOM_OK</span>' not in s_dom and "&lt;script&gt;" in s_dom
        record("XSS-REG-02", "Reflected XSS thực thi JavaScript trên trình duyệt thật (Headless Chrome)",
               v_exec and s_not_exec,
               f"vuln_js_executed={v_exec}, secured_blocked={s_not_exec}")
    else:
        record("XSS-REG-02", "Reflected XSS trình duyệt thật", False, "Không tìm thấy Chrome/Edge")

    # 3. XSS-04 / XSS-05: Stored XSS vô hại (lưu qua Vulnerable -> đọc lại ở cả Vulnerable & Secured)
    sxss_payload = '<span id="sxss-box">INIT</span><script>document.getElementById("sxss-box").textContent="SXSS_DOM_OK"</script>'
    post_v = requests.post(
        f"{VULN_URL}/product",
        data={"product_id": "2", "author": "LabTester", "content": sxss_payload},
        allow_redirects=True, timeout=5
    )
    # Phiên thứ hai độc lập đọc lại từ cả Vulnerable và Secured (dùng chung CSDL!)
    v_reload = requests.get(f"{VULN_URL}/product?id=2", timeout=5)
    s_cross_read = requests.get(f"{SECURED_URL}/product?id=2", timeout=5)
    sxss_http_ok = (
        post_v.status_code == 200
        and sxss_payload in v_reload.text
        and sxss_payload not in s_cross_read.text
        and "&lt;script&gt;" in s_cross_read.text
    )
    record("XSS-REG-03", "Stored XSS lưu DB (từ Vuln) & cross-app render an toàn trên Secured",
           sxss_http_ok,
           "Bình luận lưu từ Vuln kích hoạt ở Vuln nhưng bị mã hóa hoàn toàn khi đọc trên Secured")

    # 4. Real Headless Browser DOM Execution cho Stored XSS (sau tải lại trang)
    if browser:
        _, v_sdom, _ = dump_dom(browser, f"{VULN_URL}/product?id=2")
        _, s_sdom, _ = dump_dom(browser, f"{SECURED_URL}/product?id=2")
        v_sexec = '<span id="sxss-box">SXSS_DOM_OK</span>' in v_sdom
        s_snot_exec = '<span id="sxss-box">SXSS_DOM_OK</span>' not in s_sdom and "&lt;script&gt;" in s_sdom
        record("XSS-REG-04", "Stored XSS thực thi JavaScript khi tải lại trên trình duyệt thật",
               v_sexec and s_snot_exec,
               f"vuln_js_executed={v_sexec}, secured_blocked={s_snot_exec}")
    else:
        record("XSS-REG-04", "Stored XSS trình duyệt thật", False, "Không tìm thấy Chrome/Edge")

    # 5. XSS-06: Kiểm thử validation biên, Unicode, dấu nháy, ký tự đặc biệt, ký tự điều khiển
    r_empty = requests.post(f"{SECURED_URL}/product", data={"product_id": "3", "author": "An", "content": "   "}, allow_redirects=True, timeout=5)
    r_long_a = requests.post(f"{SECURED_URL}/product", data={"product_id": "3", "author": "A" * 51, "content": "OK"}, allow_redirects=True, timeout=5)
    r_long_c = requests.post(f"{SECURED_URL}/product", data={"product_id": "3", "author": "An", "content": "B" * 1001}, allow_redirects=True, timeout=5)
    r_ctrl = requests.post(f"{SECURED_URL}/product", data={"product_id": "3", "author": "An", "content": "Bad\x00Null"}, allow_redirects=True, timeout=5)
    r_uni = requests.post(
        f"{SECURED_URL}/product",
        data={"product_id": "3", "author": "Nguyễn Hồng Sơn", "content": "Sản phẩm \"xịn\" & 'đáng tiền' (1 < 2)!"},
        allow_redirects=True, timeout=5
    )
    val_ok = (
        "không được để trống" in r_empty.text
        and "không được vượt quá 50 ký tự" in r_long_a.text
        and "không được vượt quá 1000 ký tự" in r_long_c.text
        and "ký tự điều khiển không hợp lệ" in r_ctrl.text
        and "Gửi bình luận đánh giá thành công!" in r_uni.text
        and "Nguyễn Hồng Sơn" in r_uni.text
        and "Sản phẩm &quot;xịn&quot; &amp; &#39;đáng tiền&#39; (1 &lt; 2)!" in r_uni.text
    )
    record("XSS-REG-05", "Validation đầu vào bình luận (rỗng, >50, >1000, control char, Unicode)",
           val_ok, "Chặn đúng biên/control char và giữ trọn tiếng Việt + dấu nháy + ký tự đặc biệt")

    # 6. XSS-07: Kiểm tra Security Headers & CSP trên tất cả trang chính
    expected_csp = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    hdrs_ok = True
    for path in ["/", "/login", "/search?keyword=iPhone", "/product?id=1"]:
        h = requests.get(f"{SECURED_URL}{path}", timeout=5).headers
        if not (
            h.get("Content-Security-Policy") == expected_csp
            and h.get("X-Frame-Options") == "DENY"
            and h.get("X-Content-Type-Options") == "nosniff"
            and h.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        ):
            hdrs_ok = False
    v_hdrs = requests.get(f"{VULN_URL}/", timeout=5).headers
    hdrs_ok = hdrs_ok and ("Content-Security-Policy" not in v_hdrs)
    record("XSS-REG-06", "Security Headers (CSP, X-Frame-Options, nosniff, Referrer-Policy)",
           hdrs_ok, "Đầy đủ trên /, /login, /search, /product của Secured; không có trên Vulnerable")

    # 7. XSS-08: Thuộc tính cookie phiên SECUREDSESSION (HttpOnly, SameSite=Strict, rotation, không có session_token)
    sess_s = requests.Session()
    sess_s.get(f"{SECURED_URL}/login", timeout=5)
    pre_id = sess_s.cookies.get("SECUREDSESSION")
    r_log = sess_s.post(
        f"{SECURED_URL}/login",
        data={"username": "admin", "password": "admin123_super_secret"},
        allow_redirects=False, timeout=5
    )
    sc = get_set_cookies(r_log)
    sec_c = sc.get("SECUREDSESSION", {})
    sess_ok = (
        "SECUREDSESSION" in sc
        and "session_token" not in sc
        and sec_c.get("httponly") is True
        and (sec_c.get("samesite") or "").lower() == "strict"
        and (pre_id is None or sec_c.get("value") != pre_id)
    )
    record("XSS-REG-07", "Cookie phiên SECUREDSESSION (HttpOnly, SameSite=Strict, chống Session Fixation)",
           sess_ok, f"raw='{sec_c.get('raw', '')}' (HTTP lab: Secure={sec_c.get('secure')}; bật Secure=true với TLS profile)")

    reset_db()

    passed = sum(1 for _, _, ok, _ in cases if ok)
    total = len(cases)
    print("-" * 88)
    print(f"TỔNG KẾT XSS & SESSION REGRESSION (VERIFY-02): {passed}/{total} ĐẠT")
    print("=" * 88)
    return passed == total


if __name__ == "__main__":
    sys.exit(0 if run_xss_session_regression() else 1)
