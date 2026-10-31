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

## 🚀 2. Hướng dẫn Khởi chạy Lab Môi trường (1 Lệnh)

### Yêu cầu tiên quyết:
- Đã cài đặt [Docker](https://www.docker.com/) và Docker Compose.
- Máy tính hỗ trợ kết nối mạng nội bộ giữa các container.

### Khởi chạy hệ thống:
```bash
# Di chuyển vào thư mục dự án
cd websec-owasp-sqli-xss

# Khởi chạy toàn bộ hệ thống bằng Docker Compose
docker compose up -d
```

### Các cổng truy cập dịch vụ:
- **Web TMĐT dính lỗ hổng (Vulnerable App - Java):** [http://localhost:8080](http://localhost:8080)
- **Web TMĐT đã vá bảo mật (Secured App - Java):** [http://localhost:8081](http://localhost:8081)
- **Database (MariaDB/MySQL):** `localhost:3306` (User: `db_user`, Pass: `P@ssword123`, DB: `ecommerce_db`)
- **Attacker Cookie Stealer Listener:** [http://localhost:8888](http://localhost:8888)

---

## 📂 3. Cấu trúc Thư mục

```text
├── README.md                      # Tài liệu này
├── docker-compose.yml             # Khởi tạo toàn bộ môi trường Lab Docker
├── .gitignore                     # Cấu hình bỏ qua các file rác, target & .m2
│
├── lab-environment/               # Môi trường ứng dụng
│   ├── db/
│   │   └── init.sql               # Script khởi tạo cơ sở dữ liệu mẫu
│   ├── app-vulnerable/            # Ứng dụng Java dính lỗi (SQLi, XSS)
│   │   ├── pom.xml
│   │   └── src/main/
│   │       ├── java/com/uth/websec/ (VulnerableApp, Controller, Config, Model)
│   │       └── resources/templates/ (File .html dùng th:utext unescaped)
│   └── app-secured/               # Ứng dụng Java đã vá lỗi
│       ├── pom.xml
│       └── src/main/
│           ├── java/com/uth/websec/ (SecuredApp, PreparedStatement, SecurityHeaders)
│           └── resources/templates/ (File .html dùng th:text auto-escaped)
│
├── exploits/                      # Kịch bản và công cụ tấn công demo
│   ├── sqli/                      # Payload bypass login, Union-based, SQLMap
│   └── xss/                       # Payload Stored/Reflected XSS + Server hứng Cookie
│
└── docs/                          # Tài liệu nộp giảng viên
    ├── bao_cao/                   # Khung sườn file Word báo cáo UTH
    └── slides/                    # Hướng dẫn và dàn ý Slide 25-40 trang
```

---

## 👥 4. Phân công Công việc Nhóm

| Thành viên | Vai trò | Nhiệm vụ chính |
| :--- | :--- | :--- |
| **Thành viên 1** | Trưởng nhóm / Lab Lead | Quản lý repo, dựng Docker, thực hiện demo SQL Injection (Bypass + Union). |
| **Thành viên 2** | Security Engineer | Thực hiện demo XSS (Cướp cookie), triển khai code vá lỗi và cấu hình bảo mật Java. |
| **Thành viên 3** | Kỹ sư Tài liệu / Báo cáo | Viết tài liệu Báo cáo Word theo chuẩn 4 phần của trường UTH. |
| **Thành viên 4** | Thiết kế Slide & Thuyết trình | Soạn bộ slide 25-40 trang (Font 32/26 chuẩn UTH), quay video demo dự phòng. |

---

## ⚠️ 5. Cảnh báo Pháp lý & Đạo đức
Tất cả các kịch bản và mã tấn công trong dự án này chỉ được phép thực thi trong môi trường Lab cục bộ (Docker / VirtualBox) phục vụ mục đích học tập và nghiên cứu học phần tại trường UTH. Nghiêm cấm mọi hành vi thử nghiệm trái phép trên các hệ thống bên ngoài.
