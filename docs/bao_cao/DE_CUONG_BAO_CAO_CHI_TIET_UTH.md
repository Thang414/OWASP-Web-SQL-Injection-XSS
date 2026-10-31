# ĐỀ CƯƠNG VÀ KHUNG NỘI DUNG BÁO CÁO ĐỒ ÁN (MÔN AN NINH MẠNG - UTH)

Dành cho **Thành viên 3 (Kỹ sư Tài liệu / Báo cáo)** sử dụng để copy vào file Microsoft Word theo mẫu của Trường Đại học Giao thông vận tải TP.HCM.

---

## MỤC LỤC BÁO CÁO (DỰ KIẾN: 35 - 50 TRANG)

### LỜI MỞ ĐẦU & DANH MỤC TỪ VIẾT TẮT
- Lời cảm ơn thầy/cô giảng viên hướng dẫn.
- Danh mục bảng biểu, hình vẽ.
- Danh mục từ viết tắt: OWASP, SQLi, XSS, WAF, CSP, RDBMS, PoC...

### PHẦN 1: CƠ SỞ LÝ THUYẾT & TỔNG QUAN AN NINH MẠNG
1.1. Bối cảnh an ninh thông tin trong kỷ nguyên số và thương mại điện tử.  
1.2. Tổng quan về tổ chức OWASP và danh mục OWASP Top 10 Web Application Security Risks.  
1.3. Lỗ hổng SQL Injection (SQLi):
   - 1.3.1. Khái niệm và nguyên nhân gốc rễ.
   - 1.3.2. Cơ chế thực thi câu lệnh SQL trong ứng dụng Web.
   - 1.3.3. Các hình thức SQLi phổ biến (In-band, Inferential, Out-of-band).
   - 1.3.4. Tác động của SQLi đối với doanh nghiệp (Rò rỉ dữ liệu thẻ, phá hủy CSDL).  
1.4. Lỗ hổng Cross-Site Scripting (XSS):
   - 1.4.1. Khái niệm và mô hình Same-Origin Policy (SOP).
   - 1.4.2. Phân loại XSS (Reflected XSS, Stored XSS, DOM-based XSS).
   - 1.4.3. Nguy cơ đánh cắp phiên làm việc (Session Hijacking) và giả mạo danh tính.  
1.5. Các nguyên tắc phòng thủ theo tiêu chuẩn:
   - 1.5.1. Cơ chế Parameterized Queries / Prepared Statements.
   - 1.5.2. Nguyên lý Context-aware Output Encoding / Sanitization.
   - 1.5.3. Cấu hình bảo mật trình duyệt: Cờ HttpOnly, SameSite, Secure Cookie.
   - 1.5.4. Content Security Policy (CSP) và Web Application Firewall (WAF).

### PHẦN 2: MÔ HÌNH TRIỂN KHAI VÀ THIẾT KẾ MÔI TRƯỜNG LAB
2.1. Yêu cầu thiết kế môi trường thực nghiệm an toàn.  
2.2. Sơ đồ kiến trúc hệ thống (Kiến trúc Docker Bridge Network).  
2.3. Bảng thông số kỹ thuật các thành phần trong Lab:
   - Máy tấn công (Attacker Machine / Kali Linux).
   - Máy chủ Web chứa lỗ hổng (Vulnerable E-Shop - Port 8080).
   - Máy chủ Web bảo mật (Secured E-Shop - Port 8081).
   - Cơ sở dữ liệu MySQL (Port 3306).
   - Máy chủ lắng nghe đánh cắp Cookie (Port 8888).  
2.4. Thiết kế cơ sở dữ liệu và dữ liệu mẫu (Database Schema).

### PHẦN 3: KỊCH BẢN THỰC NGHIỆM & KẾT QUẢ ĐẠT ĐƯỢC (4 BƯỚC BẮT BUỘC)
3.1. Bước 1: Khởi tạo và kiểm tra môi trường Lab (Setup).  
3.2. Bước 2: Thực nghiệm tấn công & Khai thác (Exploitation):
   - 3.2.1. Tấn công vượt qua xác thực đăng nhập bằng SQL Injection.
   - 3.2.2. Khai thác Union-based SQLi trích xuất toàn bộ mật khẩu và thẻ tín dụng.
   - 3.2.3. Thực hiện tấn công tự động với công cụ SQLMap.
   - 3.2.4. Thực nghiệm Reflected XSS qua tham số tìm kiếm.
   - 3.2.5. Tấn công Stored XSS trong bình luận sản phẩm và cướp Cookie phiên làm việc.  
3.3. Bước 3: Triển khai giải pháp phòng thủ & Khắc phục (Defense & Mitigation):
   - 3.3.1. Chuyển đổi mã nguồn sang Java PreparedStatement (JDBC Parameterized Queries).
   - 3.3.2. Xử lý Output Encoding (Thymeleaf Context-aware Escaping với `th:text`) triệt tiêu mã XSS.
   - 3.3.3. Bật cờ bảo mật `HttpOnly` cho Cookie và thiết lập HTTP Response Headers (CSP, X-Frame-Options).  
3.4. Bước 4: Kiểm tra lại và đánh giá hiệu quả phòng thủ (Verification):
   - 3.4.1. Thử nghiệm lại các payload SQLi trên ứng dụng đã vá lỗi (Port 8081).
   - 3.4.2. Thử nghiệm lại các payload XSS và kiểm tra khả năng đọc trộm Cookie bằng JavaScript.
   - 3.4.3. Bảng so sánh tổng hợp Trước vs Sau khi triển khai giải pháp.

### PHẦN 4: KẾT LUẬN & ĐÁNH GIÁ TÍNH KHẢ THI CHO DOANH NGHIỆP
4.1. Tổng kết kết quả đạt được của đồ án.  
4.2. Bài học kinh nghiệm trong xây dựng phần mềm an toàn (Secure Coding Guidelines).  
4.3. Đề xuất quy trình DevSecOps và kiểm thử bảo mật định kỳ cho doanh nghiệp vừa và nhỏ.  
4.4. Hạn chế của đồ án và hướng phát triển tiếp theo.

### TÀI LIỆU THAM KHẢO
- Giáo trình An ninh mạng / An toàn thông tin.
- Tài liệu chính thức OWASP Top 10 (https://owasp.org/Top10/).
- Tài liệu Java & Spring Security Best Practices / OWASP Cheat Sheet Series.
