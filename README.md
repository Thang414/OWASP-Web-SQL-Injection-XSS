# ĐỒ ÁN AN NINH MẠNG (UTH)
## ĐỀ TÀI: KHAI THÁC LỖ HỔNG WEB (OWASP TOP 10) VÀ GIẢI PHÁP KHẮC PHỤC
**Trọng tâm: SQL Injection & Cross-Site Scripting (XSS) trên Ứng dụng Thương mại Điện tử Giả lập (Java Spring Boot)**

---

## 📌 1. Giới thiệu Đề tài
Dự án được xây dựng nhằm phục vụ học phần An ninh mạng tại **Trường Đại học Giao thông vận tải TP.HCM (UTH)**.
Hệ thống Web TMĐT được phát triển bằng **Java (Spring Boot + Thymeleaf)** kết hợp **MariaDB / MySQL**, triển khai đầy đủ theo quy trình chuẩn 4 bước của giảng viên:
1. **Lab Setup**: Dựng môi trường Web TMĐT (Vulnerable & Secured) bằng Docker Compose.
2. **Exploitation**: Thực hiện tấn công khai thác SQL Injection (Bypass Login, Union-based, SQLMap) và XSS (Reflected & Stored Session Hijacking).
3. **Defense & Mitigation**: Áp dụng Parameterized Queries (`PreparedStatement` trong Java), Output Encoding (Thymeleaf auto-escaping `th:text`), Input Sanitization và cấu hình bảo mật HttpOnly Cookie / CSP.
4. **Verification**: Kiểm thử lại toàn bộ kịch bản để chứng minh lỗ hổng đã được vá triệt để.

---

## 🚀 2. Yêu cầu Công cụ & Hướng dẫn Khởi chạy Lab Môi trường

### 2.1 Yêu cầu công cụ và phiên bản tiên quyết:
- **Java Development Kit (JDK):** Java 17 LTS (khuyến nghị Eclipse Temurin 17; hỗ trợ JDK 17, 21, 26).
- **Apache Maven:** Phiên bản 3.9+ (để biên dịch và đóng gói ứng dụng Spring Boot).
- **Docker & Docker Compose:** Docker Engine 24.x trở lên, Docker Compose v2 trở lên (hoặc Docker Desktop 4.x).
- **Python:** Python 3.9+ (phục vụ máy chủ lắng nghe bắt cookie và chạy script kiểm thử tự động).
- **Cơ sở dữ liệu:** MariaDB 10.5+ hoặc MySQL 8.0+ (đã tích hợp sẵn container Docker).

### 2.2 Cấu hình môi trường bằng biến môi trường:
Hệ thống hỗ trợ nạp cấu hình linh hoạt qua biến môi trường (xem tệp mẫu `.env.example` tại thư mục gốc):
- `SERVER_PORT`: Cổng lắng nghe HTTP (mặc định: `8080` cho app-vulnerable, `8081` cho app-secured).
- `DB_HOST`: Địa chỉ máy chủ CSDL (`db` khi chạy container, `localhost` khi chạy trực tiếp trên máy host).
- `DB_PORT`: Cổng kết nối CSDL (mặc định: `3306`).
- `DB_NAME`: Tên cơ sở dữ liệu (mặc định: `ecommerce_db`).
- `DB_USER`: Tên tài khoản CSDL (mặc định: `db_user`).
- `DB_PASS`: Mật khẩu CSDL (mặc định: `P@ssword123`).

### 2.3 Phương án 1: Khởi chạy toàn bộ hệ thống bằng Docker Compose (Khuyến nghị cho Lab)
```bash
# Di chuyển vào thư mục dự án
cd websec-owasp-sqli-xss

# Khởi chạy toàn bộ hệ thống ở chế độ nền
docker compose up -d

# Xem trạng thái vận hành của các container
docker compose ps
```

### 2.4 Phương án 2: Khởi chạy trực tiếp bằng Maven trên máy trạm (Local Development)
Hai ứng dụng hỗ trợ cơ chế chạy độc lập bằng Maven. Nếu không tìm thấy máy chủ MariaDB ngoài, ứng dụng sẽ tự động kích hoạt CSDL giả lập H2 (MySQL Mode) và nạp dữ liệu hạt giống từ `init.sql`:

```bash
# Khởi chạy ứng dụng chứa lỗ hổng (cổng 8080)
cd lab-environment/app-vulnerable
mvn spring-boot:run

# Mở cửa sổ terminal thứ 2 để khởi chạy ứng dụng đã vá (cổng 8081)
cd lab-environment/app-secured
mvn spring-boot:run
```

### 2.5 Các cổng truy cập dịch vụ:
- **Web TMĐT dính lỗ hổng (Vulnerable App - Java):** [http://localhost:8080](http://localhost:8080)
- **Web TMĐT đã vá bảo mật (Secured App - Java):** [http://localhost:8081](http://localhost:8081)
- **Database (MariaDB/MySQL):** `localhost:3306` (User: `db_user`, Pass: `P@ssword123`, DB: `ecommerce_db`)
- **Attacker Cookie Stealer Listener (chỉ bật cho demo XSS bằng `docker compose --profile xss-demo up -d`):** [http://localhost:8888](http://localhost:8888)

---

## ⚖️ 3. Phân biệt Hai Phiên bản Ứng dụng (Vulnerable vs Secured)

Hai ứng dụng được thiết kế có cùng khung cấu trúc Spring Boot, cùng thực thể dữ liệu (`User`, `Product`, `Comment`) và cùng giao diện giao dịch TMĐT nhằm đảm bảo tính đối sánh công bằng trong các bài đo thực nghiệm. Phần biện pháp bảo vệ được chia tách và triển khai hoàn thiện tuần tự tại các task chuyên sâu:

| Tiêu chí đối sánh | Bản chứa lỗ hổng (`app-vulnerable`) | Bản đã vá bảo mật (`app-secured`) | Nhiệm vụ kỹ thuật chịu trách nhiệm |
|---|---|---|---|
| **Cổng truy cập HTTP** | Cổng `8080` (`SERVER_PORT=8080`) | Cổng `8081` (`SERVER_PORT=8081`) | `CORE-01`, `CORE-02` |
| **Tên ứng dụng Spring** | `websec-app-vulnerable` | `websec-app-secured` | `CORE-01`, `CORE-02` |
| **Xác thực và Đăng nhập** | Nối chuỗi SQL thô (`Statement`) -> Dính SQLi Auth Bypass | Câu lệnh tham số hóa (`PreparedStatement`) chống SQLi | `CORE-04`, `CORE-05`, `SQLI-05` |
| **Tìm kiếm & Chi tiết SP** | Ghép chuỗi SQL trực tiếp (`LIKE '%keyword%'`) | Tham số hóa toàn bộ câu truy vấn qua `PreparedStatement` | `SQLI-02`, `SQLI-03`, `SQLI-08`, `SQLI-09` |
| **Kết xuất giao diện HTML** | Dùng `th:utext` (không escape thẻ) -> Dính XSS thực thi mã | Dùng `th:text` (Thymeleaf auto-escaping chống XSS) | `XSS-02`, `XSS-03`, `XSS-07` |
| **Bảo vệ Cookie & Phiên** | Cookie `session_token` đặt `HttpOnly=false` (cho phép cướp phiên) | Cookie `SECUREDSESSION` với `HttpOnly` và `SameSite=Strict`. Bật `SESSION_COOKIE_SECURE=true` khi dùng HTTPS | `CORE-05`, `XSS-10` |
| **Tiêu đề phản hồi an toàn** | Không cấu hình Security Headers | Bộ lọc `SecurityHeadersFilter` bổ sung CSP, X-Frame-Options | `XSS-09` |
| **Xử lý dữ liệu đầu vào** | Nhận chuỗi thô, không lọc thẻ nguy hiểm | Cắt tỉa khoảng trắng và giới hạn độ dài ký tự bình luận | `XSS-08` |

---

## 📂 4. Cấu trúc Thư mục

```text
├── README.md                      # Hướng dẫn tổng thể, công cụ, khởi chạy và phân biệt 2 app
├── docker-compose.yml             # Khởi tạo toàn bộ môi trường Lab Docker (3 dịch vụ mặc định)
├── .env.example                   # Tệp mẫu cấu hình biến môi trường kết nối CSDL và cổng
├── .gitignore                     # Cấu hình bỏ qua các file rác, target & .m2
│
├── lab-environment/               # Môi trường ứng dụng
│   ├── db/
│   │   └── init.sql               # Script khởi tạo cơ sở dữ liệu mẫu và cơ chế hoàn nguyên
│   ├── app-vulnerable/            # Ứng dụng Java dính lỗi (SQLi, XSS) - Cổng 8080
│   │   ├── pom.xml
│   │   └── src/main/
│   │       ├── java/com/uth/websec/ (VulnerableApp, Controller, Config, Model)
│   │       └── resources/templates/ (File .html dùng th:utext unescaped)
│   └── app-secured/               # Ứng dụng Java đã vá lỗi - Cổng 8081
│       ├── pom.xml
│       └── src/main/
│           ├── java/com/uth/websec/ (SecuredApp, PreparedStatement, SecurityHeaders)
│           └── resources/templates/ (File .html dùng th:text auto-escaped)
│
├── scripts/                       # Bộ công cụ tự động hóa lab
│   ├── reset_db.ps1               # Script PowerShell hoàn nguyên dữ liệu CSDL (Windows)
│   ├── reset_db.sh                # Script Bash hoàn nguyên dữ liệu CSDL (Linux/macOS)
│   └── verify_infra06.py          # Script kiểm thử tích hợp 15 kịch bản tự động
│
├── exploits/                      # Kịch bản và công cụ tấn công demo
│   ├── sqli/                      # Payload bypass login, Union-based, SQLMap
│   └── xss/                       # Payload Stored/Reflected XSS + Server hứng Cookie
│
└── docs/                          # Hồ sơ nghiệm thu & tài liệu báo cáo
    ├── tasks/                     # Hồ sơ nghiệm thu chi tiết từng task Jira (INFRA, CORE...)
    ├── bao_cao/                   # Khung sườn file Word báo cáo UTH
    └── slides/                    # Hướng dẫn và dàn ý Slide 25-40 trang
```

---

## 👥 5. Phân công Công việc Nhóm

| Thành viên | Vai trò | Nhiệm vụ chính |
| :--- | :--- | :--- |
| **Thành viên 1** | Trưởng nhóm / Lab Lead | Quản lý repo, dựng Docker, thực hiện demo SQL Injection (Bypass + Union). |
| **Thành viên 2** | Security Engineer | Thực hiện demo XSS (Cướp cookie), triển khai code vá lỗi và cấu hình bảo mật Java. |
| **Thành viên 3** | Kỹ sư Tài liệu / Báo cáo | Viết tài liệu Báo cáo Word theo chuẩn 4 phần của trường UTH. |
| **Thành viên 4** | Thiết kế Slide & Thuyết trình | Soạn bộ slide 25-40 trang (Font 32/26 chuẩn UTH), quay video demo dự phòng. |

---

## ⚠️ 6. Cảnh báo Pháp lý & Đạo đức
Tất cả các kịch bản và mã tấn công trong dự án này chỉ được phép thực thi trong môi trường Lab cục bộ (Docker / VirtualBox) phục vụ mục đích học tập và nghiên cứu học phần tại trường UTH. Nghiêm cấm mọi hành vi thử nghiệm trái phép trên các hệ thống bên ngoài.
