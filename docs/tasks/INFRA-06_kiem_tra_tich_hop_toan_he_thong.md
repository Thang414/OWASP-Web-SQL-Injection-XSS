# Hồ sơ công việc và biên bản nghiệm thu INFRA-06

## 1. Thông tin công việc

| Thuộc tính | Nội dung chi tiết |
|---|---|
| **Mã nội bộ** | `INFRA-06` |
| **Tên công việc** | Kiểm tra tích hợp toàn hệ thống |
| **Phụ trách** | `TV3` - Trần Văn Ngọc Thắng (trưởng nhóm: Ngọc Thắng) |
| **Mức ưu tiên** | Cao |
| **Mục tiêu** | Xác minh môi trường và các chức năng cơ bản trước khi thực nghiệm khai thác |
| **Sản phẩm bàn giao** | Checklist tích hợp, nhật ký khởi động hệ thống và ảnh chụp kết quả trên máy nhóm |
| **Tiêu chí hoàn thành** | Khởi động thành công 2 ứng dụng web và cơ sở dữ liệu từ hướng dẫn kho lưu trữ; ghi nhận cấu hình máy, phiên bản phần mềm và cổng truy cập; mỗi ứng dụng hoàn thành đầy đủ luồng đăng nhập, tìm kiếm, xem chi tiết, gửi bình luận, đăng xuất bằng dữ liệu giả lập; toàn bộ checklist có kết quả thực tế và trạng thái đạt/không đạt; lỗi chặn luồng được xử lý dứt điểm trước khi chuyển bước; xây dựng và kiểm tra quy trình hoàn nguyên (reset) dữ liệu cho từng lượt thử |
| **Phụ thuộc** | `ANM-27` (viết cấu hình docker-compose 4 dịch vụ), `ANM-29` (dữ liệu hạt giống init.sql), `ANM-20` (trang đăng nhập app dính lỗi), `ANM-21` (trang đăng nhập app đã vá), `ANM-22` (giao diện và điều hướng chung), `ANM-23` (bình luận và chi tiết sản phẩm) |
| **Giới hạn phạm vi** | Chỉ thực hiện trên môi trường lab cục bộ của nhóm với dữ liệu giả lập; tuyệt đối không thử nghiệm trên hệ thống bên ngoài và không thu thập thông tin cá nhân hay tài khoản thật |

## 2. Thông số cấu hình máy trạm và phiên bản môi trường

Quá trình kiểm thử tích hợp được thực hiện trực tiếp trên máy trạm thực nghiệm của nhóm với các thông số kỹ thuật được ghi nhận:

| Thành phần kiểm nghiệm | Thông số và phiên bản thực tế | Ghi chú vận hành |
|---|---|---|
| **Hệ điều hành máy trạm** | Microsoft Windows 11 Home (bản dựng 10.0.26100) | Kiến trúc 64-bit |
| **Bộ xử lý (CPU)** | AMD Ryzen 9 7945HX with Radeon Graphics | 16 nhân vật lý, 32 luồng xử lý |
| **Bộ nhớ truy xuất ngẫu nhiên (RAM)** | 15.69 GB (tổng dung lượng khả dụng) | Đảm bảo tải cho cụm 4 container |
| **Nền tảng ảo hóa Docker** | Docker Desktop 4.69.0 / Docker Engine Client 29.4.0 | Quản lý vòng đời dịch vụ qua WSL 2 |
| **Công cụ điều phối** | Docker Compose v5.1.1 | Khởi chạy cụm container qua tệp `docker-compose.yml` |
| **Bộ công cụ phát triển máy trạm** | Java JDK 26.0.1, Apache Maven 3.9.16, Python 3.11.0 | Phục vụ biên dịch và chạy kịch bản tự động |
| **Cổng truy cập ứng dụng dính lỗi** | `http://localhost:8080` (`websec_app_vulnerable`) | Java 17 Temurin, Spring Boot 3.2.5, Tomcat 8080 |
| **Cổng truy cập ứng dụng đã vá** | `http://localhost:8081` (`websec_app_secured`) | Java 17 Temurin, Spring Boot 3.2.5, Tomcat 8081 |
| **Cổng hứng cookie của kẻ tấn công** | `http://localhost:8888` (`websec_cookie_stealer`) | Máy chủ Python 3.9 lắng nghe tại `/steal` |
| **Cơ sở dữ liệu quan hệ** | MariaDB 10.5.29 (`websec_mysql_db`) | Cổng nội bộ 3306, cơ sở dữ liệu `ecommerce_db` |

## 3. Nhật ký khởi động hệ thống

Toàn bộ hệ thống lab được khởi động từ thư mục gốc thông qua lệnh:

```bash
docker compose up -d
```

Trạng thái vận hành của các container sau khi khởi chạy:

| Tên container | Hình ảnh Docker | Trạng thái | Cổng liên kết |
|---|---|---|---|
| `websec_mysql_db` | `mariadb:10.5` | Up (healthy) | `3306/tcp` (mạng nội bộ `websec_net`) |
| `websec_app_vulnerable` | `websec-app-vulnerable:1.0.0` | Up (running) | `0.0.0.0:8080->8080/tcp` |
| `websec_app_secured` | `websec-app-secured:1.0.0` | Up (running) | `0.0.0.0:8081->8081/tcp` |
| `websec_cookie_stealer` | `python:3.9-slim` | Up (running) | `0.0.0.0:8888->8888/tcp` |

Tệp nhật ký chi tiết quá trình khởi động được lưu trữ tại [infra-06_startup.log](file:///d:/websec-owasp-sqli-xss/docs/tasks/logs/infra-06_startup.log).

## 4. Xử lý lỗi chặn luồng trước khi chuyển bước

Trong quá trình khởi tạo và kiểm tra quy trình hoàn nguyên cơ sở dữ liệu, nhóm đã phát hiện và xử lý triệt để lỗi chặn luồng:

- **Mô tả sự cố phát sinh:** Khi thực thi nạp lại tệp `lab-environment/db/init.sql` để đưa dữ liệu về trạng thái ban đầu, hệ quản trị cơ sở dữ liệu MariaDB thông báo lỗi `ERROR 1451 (23000): Cannot delete or update a parent row: a foreign key constraint fails`. Lệnh `DROP TABLE IF EXISTS products;` thất bại do bảng `comments` đang nắm giữ khóa ngoại tham chiếu tới trường `id` của bảng `products`.
- **Nguyên nhân kỹ thuật:** Tệp `init.sql` ban đầu đặt lệnh xóa bảng `products` trước bảng `comments`, đồng thời không tạm thời vô hiệu hóa cờ kiểm tra toàn vẹn khóa ngoại trong phiên khởi tạo lại.
- **Người xử lý:** `TV3` - Trần Văn Ngọc Thắng.
- **Biện pháp khắc phục đã triển khai:**
  1. Thêm chỉ thị `SET FOREIGN_KEY_CHECKS = 0;` ở đầu tệp `init.sql` và khôi phục `SET FOREIGN_KEY_CHECKS = 1;` sau khi hoàn tất tạo cấu trúc bảng.
  2. Điều chỉnh thứ tự xóa bảng chuẩn tắc: xóa bảng phụ thuộc `comments` trước, sau đó mới xóa bảng cha `products` và `users`.
  3. Cập nhật kịch bản hoàn nguyên dữ liệu tự động (`reset_db.ps1` và `reset_db.sh`) để nhóm kiểm thử có thể làm sạch môi trường chỉ bằng một lệnh duy nhất.
- **Kết quả nghiệm thu lỗi:** Lỗi chặn luồng đã được giải quyết 100%. Lệnh reset thực thi trơn tru mà không phát sinh bất kỳ cảnh báo hay lỗi vi phạm ràng buộc nào.

## 5. Danh sách kiểm tra tích hợp và kết quả thực tế

Kịch bản kiểm tra tích hợp tự động được viết tại [verify_infra06.py](file:///d:/websec-owasp-sqli-xss/scripts/verify_infra06.py). Kết quả thực nghiệm đo lường trên máy nhóm:

| Mã kịch bản | Nội dung kiểm tra | Mục tiêu thực nghiệm | Kết quả thực tế đo lường | Trạng thái |
|---|---|---|---|---|
| `INFRA-06-01` | Kết nối cơ sở dữ liệu MariaDB và xác minh số lượng bản ghi hạt giống | `websec_mysql_db` | Truy vấn thành công: 4 tài khoản người dùng, 5 sản phẩm, 3 bình luận mẫu ban đầu | Đạt (`PASS`) |
| `INFRA-06-02` | Dịch vụ lắng nghe cookie của kẻ tấn công (cookie stealer) | `cookie-stealer` (8888) | Gửi yêu cầu `/steal?cookie=ping`, máy chủ trả về mã HTTP 200 kèm nội dung xác nhận | Đạt (`PASS`) |
| `INFRA-06-03` | Nạp trang chủ và hiển thị danh mục sản phẩm trên ứng dụng dính lỗi | `app-vulnerable` (8080) | Mã HTTP 200, phản hồi 15.612 bytes, kết xuất đầy đủ các sản phẩm mẫu | Đạt (`PASS`) |
| `INFRA-06-04` | Đăng nhập tài khoản giả lập (`nguyenvana` / `pass123456`) và lưu phiên | `app-vulnerable` (8080) | Chuyển hướng 302 về trang chủ, hiển thị tên Nguyễn Văn A, cookie `session_token` không có cờ `HttpOnly` (phục vụ demo tấn công) | Đạt (`PASS`) |
| `INFRA-06-05` | Tìm kiếm sản phẩm theo từ khóa (`keyword=iPhone`) | `app-vulnerable` (8080) | Mã HTTP 200, hiển thị chính xác sản phẩm iPhone 15 Pro Max và câu truy vấn nối chuỗi | Đạt (`PASS`) |
| `INFRA-06-06` | Xem chi tiết sản phẩm và danh sách đánh giá (`id=1`) | `app-vulnerable` (8080) | Mã HTTP 200, nạp đúng thông tin sản phẩm và danh sách bình luận hiện có từ cơ sở dữ liệu | Đạt (`PASS`) |
| `INFRA-06-07` | Gửi bình luận mới bằng dữ liệu giả lập | `app-vulnerable` (8080) | Gửi biểu mẫu thành công, bình luận mới lưu vào cơ sở dữ liệu và hiển thị ngay trên giao diện | Đạt (`PASS`) |
| `INFRA-06-08` | Đăng xuất người dùng và thu hồi phiên | `app-vulnerable` (8080) | Chuyển hướng 302 về `/login.php`, hủy `HttpSession`, xóa cookie, giao diện trở về trạng thái khách vãng lai | Đạt (`PASS`) |
| `INFRA-06-09` | Nạp trang chủ, danh mục sản phẩm và kiểm tra tiêu đề bảo mật (security headers) | `app-secured` (8081) | Mã HTTP 200, kết xuất danh mục sản phẩm, phản hồi chứa đầy đủ tiêu đề bảo mật `Content-Security-Policy` và `X-Frame-Options` | Đạt (`PASS`) |
| `INFRA-06-10` | Đăng nhập tài khoản quản trị giả lập (`admin` / `admin123_super_secret`) | `app-secured` (8081) | Xác thực qua `PreparedStatement`, hiển thị đúng họ tên Quản Trị Viên Hệ Thống, cấp quyền `admin`, cookie có cờ `HttpOnly` và `SameSite=Strict` | Đạt (`PASS`) |
| `INFRA-06-11` | Tìm kiếm sản phẩm an toàn (`keyword=Samsung`) | `app-secured` (8081) | Mã HTTP 200, hiển thị sản phẩm Samsung Galaxy S24 Ultra, câu lệnh SQL được che chắn an toàn | Đạt (`PASS`) |
| `INFRA-06-12` | Xem chi tiết sản phẩm và danh sách đánh giá (`id=2`) | `app-secured` (8081) | Mã HTTP 200, kết xuất sản phẩm id=2 và danh sách đánh giá của khách hàng | Đạt (`PASS`) |
| `INFRA-06-13` | Gửi bình luận mới trên ứng dụng đã vá bảo mật | `app-secured` (8081) | Thực thi chèn dữ liệu qua câu lệnh tham số hóa (`PreparedStatement`), hiển thị bình luận mới hợp lệ | Đạt (`PASS`) |
| `INFRA-06-14` | Đăng xuất người dùng và thu hồi phiên bảo mật | `app-secured` (8081) | Chuyển hướng 302, hủy phiên `HttpSession`, đặt cookie `session_token` với `Max-Age=0`, tải lại trang chủ xác nhận trạng thái chưa đăng nhập | Đạt (`PASS`) |
| `INFRA-06-15` | Kích hoạt và kiểm tra quy trình hoàn nguyên (reset) dữ liệu lab | `websec_mysql_db` | Thực thi `scripts/reset_db.ps1`, số bình luận từ 5 (có 2 bình luận test) trở về đúng 3 bản ghi hạt giống gốc, cấu trúc bảng được tái lập toàn vẹn | Đạt (`PASS`) |

## 6. Quy trình hoàn nguyên dữ liệu cho từng lượt thử nghiệm

Để đảm bảo tính độc lập và độ tin cậy của các lượt thực nghiệm tấn công (tiêm mã truy vấn SQL và chèn mã kịch bản liên trang XSS), quy trình reset dữ liệu được chuẩn hóa như sau:

1. **Tệp kịch bản hoàn nguyên:**
   - Phiên bản PowerShell (cho môi trường Windows): [reset_db.ps1](file:///d:/websec-owasp-sqli-xss/scripts/reset_db.ps1).
   - Phiên bản Bash shell (cho môi trường Linux/macOS): [reset_db.sh](file:///d:/websec-owasp-sqli-xss/scripts/reset_db.sh).
2. **Cách thức thực thi:**
   ```powershell
   # Chạy trên máy Windows lab
   powershell -ExecutionPolicy Bypass -File scripts/reset_db.ps1
   ```
3. **Cơ chế xác minh:**
   - Kịch bản đọc tệp dữ liệu hạt giống chuẩn [init.sql](file:///d:/websec-owasp-sqli-xss/lab-environment/db/init.sql).
   - Bơm trực tiếp vào tiến trình MariaDB bên trong container `websec_mysql_db`.
   - Chạy lệnh đối soát tự động: kiểm tra bảng `users` luôn có đủ 4 tài khoản, bảng `products` có 5 sản phẩm và bảng `comments` được xóa sạch các payload rác, trả về đúng 3 bình luận mẫu.

## 7. Minh chứng hình ảnh nghiệm thu thực tế trên máy nhóm

Tất cả các hình ảnh minh chứng dưới đây được chụp thực tế trực tiếp từ máy trạm của nhóm thông qua trình duyệt web không giao diện (headless browser) truy xuất vào các cổng đang mở:

| STT | Tên tệp ảnh minh chứng | Cổng truy cập | Nội dung và chức năng hiển thị |
|---|---|---|---|
| 1 | [01_vulnerable_homepage_8080.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/01_vulnerable_homepage_8080.png) | `8080` | Trang chủ ứng dụng dính lỗi, danh mục thiết bị và thanh điều hướng |
| 2 | [02_vulnerable_login_8080.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/02_vulnerable_login_8080.png) | `8080` | Giao diện đăng nhập và bảng tra cứu tài khoản giả lập trên ứng dụng dính lỗi |
| 3 | [03_vulnerable_search_8080.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/03_vulnerable_search_8080.png) | `8080` | Kết quả tìm kiếm từ khóa `iPhone` và truy vấn SQL mẫu trên ứng dụng dính lỗi |
| 4 | [04_vulnerable_product_comments_8080.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/04_vulnerable_product_comments_8080.png) | `8080` | Trang chi tiết sản phẩm id=1 và danh sách bình luận đã thêm dữ liệu giả lập |
| 5 | [05_secured_homepage_8081.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/05_secured_homepage_8081.png) | `8081` | Trang chủ ứng dụng đã vá bảo mật với giao diện chuẩn và tiêu đề CSP |
| 6 | [06_secured_login_8081.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/06_secured_login_8081.png) | `8081` | Giao diện đăng nhập an toàn của ứng dụng đã vá bảo mật |
| 7 | [07_secured_search_8081.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/07_secured_search_8081.png) | `8081` | Kết quả tìm kiếm từ khóa `Samsung` bằng truy vấn tham số hóa |
| 8 | [08_secured_product_comments_8081.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/08_secured_product_comments_8081.png) | `8081` | Trang chi tiết sản phẩm id=2 và danh sách bình luận đã được bảo vệ trên ứng dụng đã vá |
| 9 | [09_cookie_stealer_listener_8888.png](file:///d:/websec-owasp-sqli-xss/docs/tasks/screenshots/09_cookie_stealer_listener_8888.png) | `8888` | Phản hồi xác nhận từ máy chủ lắng nghe cookie của kẻ tấn công tại cổng 8888 |

## 8. Kết luận nghiệm thu nhiệm vụ INFRA-06

Nhiệm vụ `INFRA-06` đã hoàn thành 100% các tiêu chí nghiệm thu đề ra:
- Khởi động thành công toàn bộ 4 dịch vụ trong hệ sinh thái lab.
- Ghi nhận đầy đủ thông số phần cứng máy trạm, phiên bản phần mềm và cấu hình mạng nội bộ.
- Kiểm tra toàn diện 15 kịch bản tích hợp chức năng cơ bản trên cả hai phiên bản ứng dụng dính lỗi và ứng dụng đã vá.
- Phát hiện và xử lý dứt điểm lỗi chặn luồng liên quan tới ràng buộc khóa ngoại trong CSDL.
- Xây dựng và kiểm chứng quy trình reset dữ liệu hoàn chỉnh, phục vụ cho các pha thực nghiệm khai thác lỗ hổng tiếp theo.
