# HƯỚNG DẪN THIẾT KẾ SLIDE THUYẾT TRÌNH (CHUẨN 25 - 40 SLIDE UTH)

Dành cho **Thành viên 4 (Thiết kế Slide & Thuyết trình)**.

---

## ⚠️ CÁC QUY CHUẨN BẮT BUỘC TỪ GIẢNG VIÊN:
1. **Mẫu Slide:** Bắt buộc sử dụng Template slide chính thức của Trường ĐH Giao thông vận tải TP.HCM (UTH).
2. **Cỡ chữ:**
   - **Tiêu đề Slide:** Cỡ chữ **32**, in đậm.
   - **Nội dung Slide:** Cỡ chữ **26**, gạch đầu dòng rõ ràng, súc tích (tránh viết cả đoạn văn dài).
3. **Số lượng:** Từ **25 đến 40 slide** (chưa tính các slide chào đầu và cảm ơn cuối).

---

## BỐ CỤC PHÂN PHỐI 32 SLIDE GỢI Ý CHI TIẾT:

- **Slide 1:** Trang bìa (Tên đề tài, Giảng viên hướng dẫn, Danh sách sinh viên thực hiện, Logo UTH).
- **Slide 2:** Mục tiêu đề tài & Ý nghĩa thực tiễn.
- **Slide 3:** Nội dung trình bày (Agenda: 4 phần chính).

### PHẦN 1: CƠ SỞ LÝ THUYẾT (Slide 4 - 8)
- **Slide 4:** Tổng quan về OWASP và OWASP Top 10 rủi ro bảo mật Web.
- **Slide 5:** Lỗ hổng SQL Injection: Cơ chế và tác hại với CSDL.
- **Slide 6:** Phân loại SQL Injection (In-band, Blind, Out-of-band).
- **Slide 7:** Lỗ hổng Cross-Site Scripting (XSS): Reflected, Stored, DOM.
- **Slide 8:** Tác hại của XSS: Đánh cắp Cookie & Chiếm quyền điều khiển phiên (Session Hijacking).

### PHẦN 2: MÔ HÌNH LAB THỰC NGHIỆM (Slide 9 - 13)
- **Slide 9:** Sơ đồ mạng tổng quan (Kiến trúc Docker cô lập mạng).
- **Slide 10:** Thông số kỹ thuật các thành phần (Kali, Web Port 8080, Web Port 8081, DB, Listener).
- **Slide 11:** Giới thiệu Ứng dụng TMĐT giả lập (Các tính năng tìm kiếm, bình luận, đăng nhập).
- **Slide 12:** Cấu trúc Cơ sở dữ liệu mẫu (Bảng users, products, comments).
- **Slide 13:** Quy trình thực nghiệm chuẩn 4 bước của nhóm.

### PHẦN 3: KỊCH BẢN DEMO THỰC NGHIỆM (Slide 14 - 27) - [TRỌNG TÂM ĐIỂM SỐ]
- **Slide 14:** BƯỚC 1: Thiết lập môi trường Lab (Khởi chạy bằng Docker Compose).
- **Slide 15:** BƯỚC 2: Khai thác SQLi - Tấn công vượt qua xác thực đăng nhập (Bypass Auth).
- **Slide 16:** BƯỚC 2: Phân tích câu truy vấn SQL bị tiêm mã độc tại Backend.
- **Slide 17:** BƯỚC 2: Khai thác Union-based SQLi trích xuất toàn bộ mật khẩu người dùng.
- **Slide 18:** BƯỚC 2: Tấn công tự động hóa bằng SQLMap (Ảnh chụp kết quả dump CSDL).
- **Slide 19:** BƯỚC 2: Khai thác Reflected XSS qua thanh tìm kiếm sản phẩm.
- **Slide 20:** BƯỚC 2: Khai thác Stored XSS trong bình luận sản phẩm (Ảnh chụp script độc).
- **Slide 21:** BƯỚC 2: Demo cướp Cookie phiên và chiếm đoạt tài khoản (Session Hijacking).
- **Slide 22:** BƯỚC 3: Giải pháp phòng thủ SQLi - Triển khai PreparedStatement trong Java.
- **Slide 23:** BƯỚC 3: So sánh mã nguồn trước và sau khi vá lỗi SQLi (Diff code trực quan).
- **Slide 24:** BƯỚC 3: Giải pháp phòng thủ XSS - Output Encoding (Thymeleaf th:text auto-escaping).
- **Slide 25:** BƯỚC 3: Cấu hình bảo mật nâng cao: Bật cờ HttpOnly cho Cookie và CSP Header.
- **Slide 26:** BƯỚC 4: Kiểm tra lại (Verification) - Thử lại các payload SQLi trên hệ thống đã vá.
- **Slide 27:** BƯỚC 4: Kiểm tra lại (Verification) - Thử lại XSS và xác minh Cookie được bảo vệ an toàn.

### PHẦN 4: KẾT LUẬN & ĐÁNH GIÁ (Slide 28 - 31)
- **Slide 28:** Bảng tổng hợp so sánh Trước vs Sau khi áp dụng giải pháp.
- **Slide 29:** Bài học kinh nghiệm & Tiêu chuẩn lập trình an toàn (Secure Coding) cho doanh nghiệp.
- **Slide 30:** Đề xuất quy trình DevSecOps cho các hệ thống TMĐT.
- **Slide 31:** Đánh giá tính khả thi và hướng mở rộng.

### KẾT THÚC (Slide 32 - 33)
- **Slide 32:** Q&A - Nhóm sẵn sàng lắng nghe câu hỏi từ Thầy/Cô và các bạn.
- **Slide 33:** Lời cảm ơn.
