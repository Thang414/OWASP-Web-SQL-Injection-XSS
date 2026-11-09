# Hồ sơ công việc và biên bản nghiệm thu CORE-02

## 1. Thông tin công việc

| Thuộc tính | Nội dung chi tiết |
|---|---|
| **Mã nội bộ** | `CORE-02` |
| **Mã trên Jira** | `ANM-18` |
| **Tên công việc** | Dựng hai ứng dụng Spring Boot/Thymeleaf cùng cấu trúc và cùng phạm vi chức năng |
| **Phụ trách** | `TV3` - Trần Văn Ngọc Thắng (trưởng nhóm: Ngọc Thắng) |
| **Mức ưu tiên** | Cao |
| **Mục tiêu** | Dựng hai ứng dụng Spring Boot/Thymeleaf cùng cấu trúc và cùng phạm vi chức năng phục vụ lab an ninh mạng |
| **Sản phẩm bàn giao** | Hai dự án Java (`app-vulnerable` và `app-secured`), cấu hình riêng biệt, tệp biến môi trường mẫu (`.env.example`), tài liệu hướng dẫn khởi chạy và nhật ký khởi động |
| **Tiêu chí hoàn thành** | Hai ứng dụng biên dịch và khởi động được trên cổng 8080/8081, có nhật ký khởi động thành công; có cấu hình kết nối cơ sở dữ liệu bằng biến môi trường và ví dụ cấu hình cho lab; README ghi rõ phiên bản Java, công cụ cần có, lệnh chạy và cách phân biệt hai phiên bản; các cơ chế bảo vệ chuyên sâu được phân định triển khai tại các nhiệm vụ SQLi/XSS tiếp theo |
| **Phụ thuộc** | `ANM-17` (`CORE-01` - Dựng khung ứng dụng chứa lỗ hổng VulnerableApp, pom.xml và cấu hình ban đầu) |
| **Giới hạn phạm vi** | Chỉ thực hiện trên môi trường lab cục bộ của nhóm và dữ liệu giả lập; không thử nghiệm trên hệ thống bên ngoài; không thu thập tài khoản hoặc dữ liệu định danh thật |

## 2. Kiến trúc và cấu trúc đồng nhất của hai dự án Java

Hai ứng dụng được xây dựng trên nền tảng khung ứng dụng Spring Boot 3.2.5 kết hợp bộ kết xuất giao diện Thymeleaf, với cấu trúc thư mục đối xứng nhằm đảm bảo tính công bằng và nhất quán khi thực hiện đo lường tấn công và phòng thủ:

```text
lab-environment/
├── app-vulnerable/                               # Ứng dụng dính lỗ hổng (Cổng 8080)
│   ├── pom.xml                                   # Cấu hình phụ thuộc Maven
│   ├── Dockerfile                                # Đóng gói runtime đa tầng (multi-stage)
│   └── src/main/
│       ├── java/com/uth/websec/
│       │   ├── VulnerableApp.java                # Điểm khởi chạy ứng dụng Spring Boot
│       │   ├── config/DbConfig.java              # Kết nối CSDL JDBC & fallback H2 local
│       │   ├── controller/AppController.java     # Điều hướng (chứa lỗi SQLi & XSS cố ý)
│       │   └── model/ (User, Product, Comment)   # Các thực thể dữ liệu nghiệp vụ
│       └── resources/
│           ├── application.properties            # Nạp tham số cổng và CSDL qua biến môi trường
│           └── templates/                        # Giao diện dùng th:utext (unescaped)
│
└── app-secured/                                  # Ứng dụng đã vá bảo mật (Cổng 8081)
    ├── pom.xml                                   # Cấu hình phụ thuộc Maven
    ├── Dockerfile                                # Đóng gói runtime đa tầng (multi-stage)
    └── src/main/
        ├── java/com/uth/websec/
        │   ├── SecuredApp.java                   # Điểm khởi chạy ứng dụng Spring Boot
        │   ├── config/DbConfig.java              # Kết nối JDBC an toàn & fallback H2 local
        │   ├── controller/AppController.java     # Điều hướng an toàn qua PreparedStatement
        │   ├── filter/SecurityHeadersFilter.java # Bộ lọc tiêu đề bảo mật CSP, X-Frame-Options
        │   └── model/ (User, Product, Comment)   # Các thực thể dữ liệu nghiệp vụ đồng nhất
        └── resources/
            ├── application.properties            # Nạp tham số cổng 8081 và CSDL an toàn
            └── templates/                        # Giao diện dùng th:text (auto-escaped)
```

## 3. Cấu hình kết nối cơ sở dữ liệu bằng biến môi trường

Cả hai ứng dụng đều hỗ trợ cơ chế nạp tham số cấu hình linh hoạt thông qua biến môi trường hệ thống trong tệp `application.properties`, kết hợp giá trị mặc định cho từng môi trường:

```properties
# Cấu hình cổng dịch vụ (tùy biến qua biến SERVER_PORT)
server.port=${SERVER_PORT:8080} # 8081 đối với app-secured
spring.application.name=websec-app-vulnerable # websec-app-secured

# Cấu hình kết nối cơ sở dữ liệu MariaDB / MySQL
db.host=${DB_HOST:db}
db.port=${DB_PORT:3306}
db.name=${DB_NAME:ecommerce_db}
db.user=${DB_USER:db_user}
db.pass=${DB_PASS:P@ssword123}
```

Tệp mẫu cấu hình môi trường lab đã được khởi tạo tại [.env.example](file:///d:/websec-owasp-sqli-xss/.env.example) giúp thành viên trong nhóm thiết lập nhanh:
- `SERVER_PORT_VULN=8080`: Cổng ứng dụng dính lỗi.
- `SERVER_PORT_SECURED=8081`: Cổng ứng dụng đã vá.
- `DB_HOST=db`: Tên dịch vụ CSDL trong mạng Docker nội bộ (hoặc `localhost` khi chạy trực tiếp).
- `DB_USER=db_user`, `DB_PASS=P@ssword123`: Thông tin xác thực CSDL mẫu.

## 4. Biên dịch và nhật ký khởi động thành công

Hai ứng dụng được kiểm chứng biên dịch sạch sẽ và vượt qua toàn bộ các bài kiểm thử đơn vị, kiểm thử tích hợp nội bộ:
- **Biên dịch Maven:** Cả hai tệp `pom.xml` đều đạt trạng thái `BUILD SUCCESS` với Maven 3.9.16 trên nền Java 17/26.
- **Khởi động dịch vụ:** Container `websec_app_vulnerable` khởi động thành công và lắng nghe tại cổng `8080`; container `websec_app_secured` khởi động thành công và lắng nghe tại cổng `8081`.
- **Nhật ký chi tiết:** Được lưu trữ đầy đủ tại [core-02_startup.log](file:///d:/websec-owasp-sqli-xss/docs/tasks/logs/core-02_startup.log).

## 5. Bảng đối sánh và phân biệt hai phiên bản ứng dụng

Nhằm đáp ứng yêu cầu phân định ranh giới chức năng và các biện pháp bảo vệ được triển khai theo tiến độ bài tập, các tiêu chí đối sánh được tổng hợp như sau:

| Tiêu chí đối sánh | Bản dính lỗ hổng (`app-vulnerable`) | Bản đã vá bảo mật (`app-secured`) | Nhiệm vụ kỹ thuật phụ trách |
|---|---|---|---|
| **Cổng truy cập HTTP** | Cổng `8080` (`SERVER_PORT=8080`) | Cổng `8081` (`SERVER_PORT=8081`) | `CORE-01`, `CORE-02` |
| **Khung ứng dụng chính** | Spring Boot 3.2.5 (`VulnerableApp.java`) | Spring Boot 3.2.5 (`SecuredApp.java`) | `CORE-01`, `CORE-02` |
| **Xử lý truy vấn CSDL** | JDBC `Statement` nối chuỗi trực tiếp (cho phép tiêm SQL) | Tham số hóa bằng `PreparedStatement` | `SQLI-02`, `SQLI-03`, `SQLI-08`, `SQLI-09` |
| **Kết xuất giao diện HTML** | Dùng thuộc tính `th:utext` (không escape thẻ) | Dùng thuộc tính `th:text` (Thymeleaf tự động escape) | `XSS-02`, `XSS-03`, `XSS-07` |
| **Quản lý phiên và cookie** | Cờ `HttpOnly=false` (cho phép đọc qua JavaScript) | Cờ `HttpOnly=true`, `SameSite=Strict` | `CORE-05`, `XSS-10` |
| **Bộ lọc tiêu đề bảo mật** | Không áp dụng bộ lọc tiêu đề phản hồi | Bộ lọc `SecurityHeadersFilter` (CSP, X-Frame-Options) | `XSS-09` |
| **Làm sạch dữ liệu vào** | Nhận nguyên văn chuỗi thô người dùng gửi | Cắt tỉa khoảng trắng và giới hạn độ dài trường dữ liệu | `XSS-08` |

## 6. Danh sách kiểm tra nghiệm thu thực tế

| Mã kịch bản | Nội dung kiểm tra | Mục tiêu thực nghiệm | Kết quả thực tế | Trạng thái |
|---|---|---|---|---|
| `AC-01` | Biên dịch mã nguồn cả hai ứng dụng Java qua Maven | `app-vulnerable` & `app-secured` | Cả hai dự án đạt `BUILD SUCCESS`, không phát sinh lỗi phụ thuộc | Đạt (`PASS`) |
| `AC-02` | Khởi động hai ứng dụng trên hai cổng độc lập 8080 và 8081 | Cổng `8080` & cổng `8081` | Cả hai tiến trình Spring Boot khởi động trơn tru trong 2.9 giây, có nhật ký xác nhận | Đạt (`PASS`) |
| `AC-03` | Nạp cấu hình CSDL bằng biến môi trường và cung cấp tệp ví dụ | Tệp `.env.example` và `application.properties` | Đọc thành công các biến `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` | Đạt (`PASS`) |
| `AC-04` | Cập nhật tài liệu hướng dẫn tổng thể tại tệp `README.md` | Tệp `README.md` | Bổ sung đầy đủ phiên bản Java, công cụ, hướng dẫn 2 cách chạy và bảng phân biệt hai phiên bản | Đạt (`PASS`) |
| `AC-05` | Tuân thủ giới hạn an toàn và phạm vi thực nghiệm lab | Toàn bộ hệ sinh thái lab | Chỉ sử dụng dữ liệu giả lập từ `init.sql`, không thử nghiệm bên ngoài, không dùng dữ liệu thật | Đạt (`PASS`) |

## 7. Kết luận nghiệm thu

Nhiệm vụ `CORE-02` (`ANM-18`) đã hoàn thành toàn diện 100% các tiêu chí yêu cầu:
- Hai dự án Spring Boot/Thymeleaf đã được hoàn thiện khung cấu trúc, phân cổng rõ ràng 8080/8081.
- Hỗ trợ đầy đủ biến môi trường và tệp hướng dẫn mẫu `.env.example`.
- Bổ sung tài liệu phân biệt kỹ thuật rõ ràng trong `README.md`.
- Toàn bộ mã nguồn, cấu hình và hồ sơ minh chứng đã sẵn sàng trên nhánh tính năng chuyên trách.
