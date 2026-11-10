# Hồ sơ công việc và biên bản nghiệm thu CORE-04 (ANM-20)

## 1. Thông tin công việc

| Thuộc tính | Nội dung chi tiết |
|---|---|
| **Mã nội bộ** | `CORE-04` |
| **Mã trên Jira** | `ANM-20` |
| **Tên công việc** | Tạo trang chủ, danh sách và tìm kiếm sản phẩm |
| **Phạm vi phụ trách** | `TV2` - Hồng Sơn |
| **Ưu tiên kế hoạch** | Cao |
| **Mục tiêu** | Hoàn thiện trang chủ, danh sách và tìm kiếm sản phẩm ở cả hai ứng dụng (`app-vulnerable` và `app-secured`) |
| **Sản phẩm bàn giao** | Giao diện ([`index.html`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/main/resources/templates/index.html), [`search.html`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/main/resources/templates/search.html)), xử lý phía máy chủ ([`AppController.java`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/AppController.java)) và kết quả kiểm thử chức năng ([`Core04HomeAndSearchTest.java`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/test/java/com/uth/websec/Core04HomeAndSearchTest.java), [`core-04_test.log`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/docs/tasks/logs/core-04_test.log)) |
| **Tiêu chí hoàn thành** | (1) Trang chủ lấy sản phẩm từ cơ sở dữ liệu và liên kết được đến chi tiết sản phẩm; (2) Tìm kiếm với từ khóa có kết quả, không có kết quả và rỗng có hành vi được mô tả, không gây lỗi chặn luồng; (3) Hai ứng dụng trả kết quả tương đương với dữ liệu hợp lệ; lưu ảnh hoặc log từng trường hợp |
| **Phụ thuộc** | `ANM-18` (`CORE-02` - Tạo khung hai phiên bản ứng dụng Spring Boot), `ANM-19` (`CORE-03` - Thiết kế model User, Product, Comment), `ANM-29` (`INFRA-05` - Tạo dữ liệu giả lập thương mại điện tử) |
| **Giới hạn** | Chỉ thực hiện trên lab của nhóm và dữ liệu giả; không thử nghiệm hệ thống bên ngoài. Không thu thập tài khoản hay thông tin cá nhân thật |

---

## 2. Dữ liệu sản phẩm giả lập sử dụng trong Lab (`init.sql`)

Toàn bộ danh mục sản phẩm được truy vấn trực tiếp từ bảng `products` khởi tạo tại [`lab-environment/db/init.sql`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/db/init.sql#L32-L45):

| ID (`id`) | Tên sản phẩm (`name`) | Mô tả (`description`) | Giá niêm yết (`price`) | Giá hiển thị (`formattedPrice`) | Danh mục (`category`) |
|---|---|---|---|---|---|
| `1` | **iPhone 15 Pro Max** | Điện thoại thông minh Apple 256GB Titan tự nhiên | `29990000.00` | `29.990.000 VNĐ` | `Điện thoại` |
| `2` | **Samsung Galaxy S24 Ultra** | Flagship AI Phone đỉnh cao Snapdragon 8 Gen 3 | `27490000.00` | `27.490.000 VNĐ` | `Điện thoại` |
| `3` | **Laptop Dell XPS 15** | Laptop cao cấp Intel Core i7, 16GB RAM, 512GB SSD | `35000000.00` | `35.000.000 VNĐ` | `Máy tính` |
| `4` | **MacBook Air M2** | Thiết kế siêu mỏng nhẹ, pin 18 tiếng, Apple Silicon M2 | `22500000.00` | `22.500.000 VNĐ` | `Máy tính` |
| `5` | **Tai nghe Sony WH-1000XM5** | Tai nghe chống ồn chủ động cao cấp | `7990000.00` | `7.990.000 VNĐ` | `Phụ kiện` |

---

## 3. Thiết kế kỹ thuật và đối sánh hai phiên bản ứng dụng

### 3.1. Các điểm cuối (Endpoints) và Điều hướng
- **Trang chủ & Danh sách sản phẩm:** `GET /` và `GET /index.php`
  - Truy vấn toàn bộ 5 sản phẩm từ bảng `products` (`SELECT * FROM products`) và kết xuất ra lưới thẻ sản phẩm trên `index.html`.
  - Mỗi thẻ sản phẩm gắn đường dẫn điều hướng chính xác sang trang chi tiết sản phẩm qua `/product?id={id}` (đồng thời hỗ trợ cả biến thể đường dẫn `/products/{id}` ở tầng Controller để tương thích hoàn toàn với `CORE-06`).
- **Tìm kiếm sản phẩm:** `GET /search` và `GET /search.php` (tham số `keyword`)
  - Xử lý đầy đủ 3 trường hợp đầu vào mà không gây lỗi chặn luồng (`HTTP 200 OK`):
    1. **Từ khóa có kết quả (`FOUND`):** Hiển thị danh sách các sản phẩm khớp từ khóa kèm nút `Xem chi tiết`.
    2. **Từ khóa không có kết quả (`NOT_FOUND`):** Hiển thị thông báo rõ ràng *"Không tìm thấy sản phẩm nào phù hợp với từ khóa..."*.
    3. **Từ khóa rỗng hoặc chỉ chứa khoảng trắng (`BLANK_KEYWORD`):** Nhận diện qua `keyword == null || keyword.trim().isEmpty()`, tự động truy vấn và trả về **toàn bộ 5 sản phẩm mặc định** kèm thông báo trạng thái *"Từ khóa tìm kiếm đang trống hoặc chỉ chứa khoảng trắng — Hiển thị toàn bộ danh sách sản phẩm mặc định (5 sản phẩm)"*.

### 3.2. Bảng đối sánh cơ chế xử lý giữa `app-vulnerable` (8080) và `app-secured` (8081)

| Hạng mục kỹ thuật | Bản chứa lỗ hổng (`app-vulnerable` - Cổng 8080) | Bản đã vá bảo mật (`app-secured` - Cổng 8081) | Tính tương đương với dữ liệu hợp lệ |
|---|---|---|---|
| **Truy vấn Trang chủ (`GET /`)** | Dùng `java.sql.Statement` thực thi `SELECT * FROM products` | Dùng `java.sql.PreparedStatement` thực thi `SELECT * FROM products` | Trả về cùng 5 sản phẩm, cùng định dạng giá và hình ảnh minh họa |
| **Truy vấn Tìm kiếm (`GET /search`)** | Nối chuỗi SQL trực tiếp: `SELECT id, name, description, price FROM products WHERE name LIKE '%" + keyword + "%'` (phục vụ Lab SQLi Union 4 cột) | Tham số hóa bằng `PreparedStatement`: `SELECT id, name, description, price FROM products WHERE name LIKE ?` với `pstmt.setString(1, "%" + cleanKeyword + "%")` | Với từ khóa hợp lệ (`iPhone`, `Samsung`, `Nokia...`), hai bản trả về danh sách kết quả giống nhau 100% |
| **Xử lý từ khóa rỗng / chỉ khoảng trắng** | Kiểm tra `keyword.trim().isEmpty()` -> Truy vấn `SELECT id, name, description, price FROM products` trả về đủ 5 SP mặc định | Kiểm tra `cleanKeyword.isEmpty()` -> Truy vấn `SELECT id, name, description, price FROM products` qua `PreparedStatement` trả về đủ 5 SP mặc định | Trả về cùng 5 sản phẩm mặc định và cùng thông báo trạng thái trên giao diện |
| **Kết xuất từ khóa trên `search.html`** | Dùng `th:utext="${keyword}"` (không mã hóa thực thể HTML -> phục vụ Lab Reflected XSS) | Dùng `th:text="${keyword}"` (Thymeleaf auto-escaping chống Reflected XSS) | Hiển thị văn bản giống hệt nhau đối với từ khóa tìm kiếm thông thường |
| **Ghi nhật ký Server (Server Logging)** | SLF4J Logger ghi rõ `[CORE-04][HOME]`, `[CORE-04][SEARCH][FOUND]`, `[NOT_FOUND]`, `[BLANK_KEYWORD]` | SLF4J Logger ghi rõ `[CORE-04][HOME]`, `[CORE-04][SEARCH][FOUND]`, `[NOT_FOUND]`, `[BLANK_KEYWORD]` | Định dạng log đồng nhất phục vụ đối soát nghiệm thu |

---

## 4. Danh sách kiểm tra nghiệm thu thực tế (Testing & Evidence Checklist)

Bộ kiểm thử tự động [`Core04HomeAndSearchTest.java`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/test/java/com/uth/websec/Core04HomeAndSearchTest.java) (cùng các bộ kiểm thử hồi quy `Core05LoginSessionTest` và `ModelMappingTest`) đã được thực thi trên cả hai ứng dụng:

| Mã kịch bản | Tiêu chí | Nội dung kiểm tra & Dữ liệu đầu vào | Kết quả trên `app-vulnerable` (8080) | Kết quả trên `app-secured` (8081) | Trạng thái |
|---|---|---|---|---|---|
| **AC-01** | Tiêu chí 1 & 3 | Truy cập trang chủ (`GET /`, `GET /index.php`), hiển thị danh sách 5 sản phẩm từ CSDL kèm định dạng giá VNĐ | Hiển thị đủ 5 sản phẩm (`29.990.000 VNĐ`...), log `[CORE-04][HOME] Tong so san pham: 5` | Hiển thị đủ 5 sản phẩm (`29.990.000 VNĐ`...), log `[CORE-04][HOME] Tong so san pham: 5` | Đạt (`PASS`) |
| **AC-02** | Tiêu chí 1 | Kiểm tra đường dẫn điều hướng từ danh sách sang trang chi tiết sản phẩm (`/product?id=1..5` và `/products/{id}`) | Có đủ link `/product?id=1..5`, điều hướng `HTTP 200 OK` mở đúng trang chi tiết sản phẩm | Có đủ link `/product?id=1..5`, điều hướng `HTTP 200 OK` mở đúng trang chi tiết sản phẩm | Đạt (`PASS`) |
| **AC-03** | Tiêu chí 2 (TH1) & 3 | Tìm kiếm với từ khóa có kết quả (`keyword=iPhone` -> 1 SP; `keyword=M` -> 3 SP) | Trả về đúng 1 SP (`iPhone 15 Pro Max`) và 3 SP khớp chữ `M`, log `[CORE-04][SEARCH][FOUND]` | Trả về đúng 1 SP (`iPhone 15 Pro Max`) và 3 SP khớp chữ `M`, log `[CORE-04][SEARCH][FOUND]` | Đạt (`PASS`) |
| **AC-04** | Tiêu chí 2 (TH2) & 3 | Tìm kiếm với từ khóa không có kết quả (`keyword=Nokia1280KhongTonTai`) | Không lỗi 500 (`HTTP 200`), trả về 0 SP, hiển thị thông báo không tìm thấy, log `[NOT_FOUND]` | Không lỗi 500 (`HTTP 200`), trả về 0 SP, hiển thị thông báo không tìm thấy, log `[NOT_FOUND]` | Đạt (`PASS`) |
| **AC-05** | Tiêu chí 2 (TH3) & 3 | Tìm kiếm với từ khóa rỗng (`keyword=""`) hoặc chỉ chứa khoảng trắng (`keyword="   "`) | Không lỗi 500, trả về toàn bộ 5 SP mặc định kèm thông báo trạng thái, log `[BLANK_KEYWORD]` | Không lỗi 500, trả về toàn bộ 5 SP mặc định kèm thông báo trạng thái, log `[BLANK_KEYWORD]` | Đạt (`PASS`) |

---

## 5. Minh chứng nghiệm thu (Nhật ký Server Log, Ảnh chụp & Tệp bàn giao)

### 5.1. Liên kết tệp bàn giao và ảnh chụp giao diện thực tế
- **Xử lý phía máy chủ (Backend):**
  - Bản `app-vulnerable` (8080): [`AppController.java`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/AppController.java)
  - Bản `app-secured` (8081): [`AppController.java`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-secured/src/main/java/com/uth/websec/controller/AppController.java)
- **Giao diện (Frontend Templates):**
  - Bản `app-vulnerable` (8080): [`index.html`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/main/resources/templates/index.html), [`search.html`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/main/resources/templates/search.html)
  - Bản `app-secured` (8081): [`index.html`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-secured/src/main/resources/templates/index.html), [`search.html`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-secured/src/main/resources/templates/search.html)
- **Bộ kiểm thử tự động & Nhật ký thực thi:**
  - Kiểm thử JUnit 5 + `MockMvc`: [`app-vulnerable/Core04HomeAndSearchTest.java`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-vulnerable/src/test/java/com/uth/websec/Core04HomeAndSearchTest.java), [`app-secured/Core04HomeAndSearchTest.java`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/lab-environment/app-secured/src/test/java/com/uth/websec/Core04HomeAndSearchTest.java)
  - Nhật ký kiểm thử chi tiết: [`docs/tasks/logs/core-04_test.log`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/docs/tasks/logs/core-04_test.log)
- **Ảnh chụp màn hình trang chủ và tìm kiếm sản phẩm:**
  - Trang chủ `app-vulnerable` (8080): [`01_vulnerable_homepage_8080.png`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/docs/tasks/screenshots/01_vulnerable_homepage_8080.png)
  - Tìm kiếm `app-vulnerable` (8080): [`03_vulnerable_search_8080.png`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/docs/tasks/screenshots/03_vulnerable_search_8080.png)
  - Trang chủ `app-secured` (8081): [`05_secured_homepage_8081.png`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/docs/tasks/screenshots/05_secured_homepage_8081.png)
  - Tìm kiếm `app-secured` (8081): [`07_secured_search_8081.png`](file:///d:/OWASP-Web-SQL-Injection-XSS-Project/OWASP-Web-SQL-Injection-XSS/docs/tasks/screenshots/07_secured_search_8081.png)

### 5.2. Trích xuất nhật ký kiểm thử và Server Log từng trường hợp

```text
[app-vulnerable - Cổng 8080]
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][BLANK_KEYWORD] Tu khoa rong hoac chi chua khoang trang (raw='') -> Tra ve toan bo 5 san pham mac dinh
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][BLANK_KEYWORD] Tu khoa rong hoac chi chua khoang trang (raw='   ') -> Tra ve toan bo 5 san pham mac dinh
INFO c.uth.websec.controller.AppController : [CORE-04][HOME] Hien thi trang chu (vulnerable) - Tong so san pham: 5
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][NOT_FOUND] Tu khoa='Nokia1280KhongTonTai' -> Khong tim thay san pham nao (0 ket qua)
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][FOUND] Tu khoa='iPhone' -> Tim thay 1 san pham
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][FOUND] Tu khoa='M' -> Tim thay 3 san pham
[INFO] Tests run: 5, Failures: 0, Errors: 0, Skipped: 0 -- in com.uth.websec.Core04HomeAndSearchTest
[INFO] Results: Tests run: 13, Failures: 0, Errors: 0, Skipped: 0 -> BUILD SUCCESS

[app-secured - Cổng 8081]
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][BLANK_KEYWORD] Tu khoa rong hoac chi chua khoang trang (raw='') -> Tra ve toan bo 5 san pham mac dinh
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][BLANK_KEYWORD] Tu khoa rong hoac chi chua khoang trang (raw='   ') -> Tra ve toan bo 5 san pham mac dinh
INFO c.uth.websec.controller.AppController : [CORE-04][HOME] Hien thi trang chu (secured) - Tong so san pham: 5
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][NOT_FOUND] Tu khoa='Nokia1280KhongTonTai' -> Khong tim thay san pham nao (0 ket qua)
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][FOUND] Tu khoa='iPhone' -> Tim thay 1 san pham
INFO c.uth.websec.controller.AppController : [CORE-04][SEARCH][FOUND] Tu khoa='M' -> Tim thay 3 san pham
[INFO] Tests run: 5, Failures: 0, Errors: 0, Skipped: 0 -- in com.uth.websec.Core04HomeAndSearchTest
[INFO] Results: Tests run: 13, Failures: 0, Errors: 0, Skipped: 0 -> BUILD SUCCESS
```

---

## 6. Kết luận nghiệm thu

Nhiệm vụ `CORE-04` (`ANM-20` - *Tạo trang chủ, danh sách và tìm kiếm sản phẩm*) đã hoàn thành 100% các tiêu chí yêu cầu:
1. Trang chủ lấy đầy đủ 5 sản phẩm từ cơ sở dữ liệu và liên kết chính xác đến trang chi tiết sản phẩm.
2. Chức năng tìm kiếm hoạt động ổn định với từ khóa có kết quả, không có kết quả và rỗng/chỉ chứa khoảng trắng theo đúng hành vi mô tả, không gây lỗi chặn luồng.
3. Hai phiên bản ứng dụng (`app-vulnerable` và `app-secured`) trả về kết quả tương đương nhau đối với dữ liệu hợp lệ; đã lưu đầy đủ nhật ký kiểm thử, log từng trường hợp và ảnh chụp màn hình trên nhánh `HongSon/CORE-04`.

