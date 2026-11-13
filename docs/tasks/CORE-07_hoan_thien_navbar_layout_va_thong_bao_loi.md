# BIÊN BẢN NGHIỆM THU TASK CORE-07 (ANM-23)
**Hoàn thiện navbar, layout và thông báo lỗi**

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Mã nội bộ** | `CORE-07` (`ANM-23`) |
| **Phạm vi phụ trách** | TV2 - Hồng Sơn |
| **Ưu tiên kế hoạch** | Trung bình |
| **Phụ thuộc** | [ANM-20 (`CORE-04`)](./CORE-04_trang_chu_danh_sach_va_tim_kiem_san_pham.md), [ANM-21 (`CORE-05`)](./CORE-05_luong_dang_nhap_dang_xuat_va_trang_thai_phien.md), [ANM-22 (`CORE-06`)](./CORE-06_trang_chi_tiet_san_pham_va_binh_luan.md) |
| **Trạng thái** | **HOÀN THÀNH (DONE)** |

> **Theo dõi kế hoạch & Giới hạn an toàn:**
> - Sprint, điểm ước lượng và người được giao được quản lý trực tiếp bằng trường Jira; không sao chép số sprint hoặc điểm vào mô tả.
> - Chỉ thực hiện trên lab của nhóm (`localhost`) và bộ dữ liệu giả trong [`lab-environment/db/init.sql`](../../lab-environment/db/init.sql); tuyệt đối không thử nghiệm hệ thống bên ngoài và không thu thập tài khoản hay thông tin cá nhân thật.

---

## 1. Mục tiêu & Sản phẩm bàn giao (Deliverables)

Thống nhất bố cục, thanh điều hướng và hệ thống thông báo lỗi ở cả hai ứng dụng (`app-vulnerable` và `app-secured`) để vận hành liền mạch luồng thương mại điện tử giả lập từ đầu đến cuối, đồng thời đảm bảo phiên bản `app-secured` tuân thủ nguyên tắc *Security by Design* (không rò rỉ câu lệnh SQL, cấu trúc bảng hay Stacktrace nội bộ ra giao diện).

| Hạng mục bàn giao | Tệp tin / Đường dẫn trong Repository | Mô tả |
| :--- | :--- | :--- |
| **Bố cục & Thanh điều hướng dùng chung (Vulnerable)** | [`lab-environment/app-vulnerable/src/main/resources/templates/fragments/layout.html`](../../lab-environment/app-vulnerable/src/main/resources/templates/fragments/layout.html) | Thymeleaf Fragments dùng chung: `sharedStyles`, `navbar(activePage)`, `labBanner`, `systemAlerts`, `footer` (tông màu Đỏ/Cam nhận diện cổng `8080`) |
| **Bố cục & Thanh điều hướng dùng chung (Secured)** | [`lab-environment/app-secured/src/main/resources/templates/fragments/layout.html`](../../lab-environment/app-secured/src/main/resources/templates/fragments/layout.html) | Thymeleaf Fragments dùng chung: `sharedStyles`, `navbar(activePage)`, `labBanner`, `systemAlerts`, `footer` (tông màu Xanh ngọc lục bảo nhận diện cổng `8081`) |
| **Trang báo lỗi tập trung (Vulnerable & Secured)** | [`lab-environment/app-vulnerable/src/main/resources/templates/error.html`](../../lab-environment/app-vulnerable/src/main/resources/templates/error.html), [`lab-environment/app-secured/src/main/resources/templates/error.html`](../../lab-environment/app-secured/src/main/resources/templates/error.html) | Thay thế trang Whitelabel Error mặc định bằng giao diện báo lỗi `400`/`404`/`500` thân thiện, giữ nguyên Navbar và trạng thái người dùng |
| **Bộ xử lý lỗi & Đồng bộ phiên toàn cục** | [`lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/GlobalControllerAdvice.java`](../../lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/GlobalControllerAdvice.java), [`lab-environment/app-secured/src/main/java/com/uth/websec/controller/GlobalControllerAdvice.java`](../../lab-environment/app-secured/src/main/java/com/uth/websec/controller/GlobalControllerAdvice.java) | `@ControllerAdvice` tự động nạp `user` vào `Model` trên mọi view (kể cả `error.html`) và bắt các ngoại lệ hệ thống/tham số |
| **Chuẩn hóa xử lý lỗi & Che giấu thông tin nội bộ** | [`lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/AppController.java`](../../lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/AppController.java), [`lab-environment/app-secured/src/main/java/com/uth/websec/controller/AppController.java`](../../lab-environment/app-secured/src/main/java/com/uth/websec/controller/AppController.java) | Chuẩn hóa thông báo lỗi đăng nhập, sản phẩm không tồn tại, bình luận thất bại và lỗi dịch vụ CSDL; ẩn hoàn toàn `e.getMessage()` trên `app-secured` |
| **Các trang giao diện tích hợp Layout dùng chung** | `index.html`, `search.html`, `product.html`, `login.html` (trên cả `app-vulnerable` và `app-secured`) | Toàn bộ 4 trang giao diện trong mỗi ứng dụng tái sử dụng fragments từ `fragments/layout.html` thông qua `th:replace` |
| **Bộ kiểm thử tự động (Vulnerable & Secured)** | [`lab-environment/app-vulnerable/src/test/java/com/uth/websec/Core07NavbarLayoutAndErrorTest.java`](../../lab-environment/app-vulnerable/src/test/java/com/uth/websec/Core07NavbarLayoutAndErrorTest.java), [`lab-environment/app-secured/src/test/java/com/uth/websec/Core07NavbarLayoutAndErrorTest.java`](../../lab-environment/app-secured/src/test/java/com/uth/websec/Core07NavbarLayoutAndErrorTest.java) | 6 bài kiểm thử tích hợp JUnit 5 + `MockMvc` (`CORE-07.1` → `CORE-07.6`) kiểm chứng Navbar, Layout, Thông báo lỗi, Chống lộ SQL và Luồng E2E |
| **Nhật ký kiểm thử tự động** | [`docs/tasks/logs/core-07_test.log`](./logs/core-07_test.log) | Log kết quả chạy `mvn test` (`25/25 PASS` mỗi ứng dụng) và nhật ký thực thi luồng thương mại điện tử đầy đủ |

---

## 2. Kiến trúc Bố cục Dùng chung & Cơ chế Xử lý Thông báo Lỗi

### 2.1. Tái sử dụng Bố cục và Thanh điều hướng (`templates/fragments/layout.html`)
Toàn bộ các trang `index.html`, `search.html`, `product.html`, `login.html` và `error.html` ở mỗi ứng dụng đều kế thừa 5 phân đoạn chuẩn hóa:
1. **`th:fragment="sharedStyles"`**: Cung cấp hệ thống CSS dùng chung cho `.main-navbar`, `.nav-links`, `.user-pill`, `.banner-warning`/`.banner-secured`, `.global-service-error` và `.site-footer`.
2. **`th:fragment="navbar(activePage)"`**:
   - Hiển thị thương hiệu **UTH E-Shop** kèm huy hiệu nhận diện môi trường (`⚠️ VULNERABLE LAB :8080` hoặc `🛡️ SECURED APP :8081`).
   - Liên kết điều hướng xuyên suốt giữa **Trang chủ** (`/`), **Tìm kiếm** (`/search`), **Chi tiết & Bình luận** (`/product?id=1`), tự động đánh dấu `.active` theo trang hiện tại.
   - Hiển thị nhất quán trạng thái phiên đăng nhập của người dùng trên mọi trang:
     - **Khi đã đăng nhập (`user != null`):** Hiển thị Avatar ký tự đầu + `Họ tên (username) (Quyền: role)` và nút **Đăng xuất** (`/logout`).
     - **Khi chưa đăng nhập (`user == null`):** Hiển thị trạng thái `Khách vãng lai` và nút **Đăng nhập** (`/login`).
3. **`th:fragment="labBanner"`**: Thanh băng rôn cảnh báo chế độ Lab (Đỏ cho bản Vulnerable, Xanh ngọc cho bản Secured).
4. **`th:fragment="systemAlerts"`**: Khối cảnh báo dịch vụ toàn cục `.global-service-error` tự động hiển thị khi thuộc tính `error` có mặt trong `Model`.
5. **`th:fragment="footer"`**: Chân trang thống nhất có thanh điều hướng nhanh tới các chức năng chính.

### 2.2. Đối chiếu Cơ chế Thông báo Lỗi & Bảo mật Thông tin Nội bộ

| Tình huống lỗi | Hành vi trên `app-vulnerable` (Cổng `8080`) | Hành vi trên `app-secured` (Cổng `8081`) |
| :--- | :--- | :--- |
| **1. Đăng nhập sai hoặc bỏ trống thông tin** | Báo rõ: *"Vui lòng nhập tên đăng nhập!"* hoặc *"Tên đăng nhập hoặc mật khẩu không chính xác!"* | Báo rõ: *"Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu!"* hoặc *"Tên đăng nhập hoặc mật khẩu không chính xác!"* |
| **2. Sản phẩm không tồn tại (`id=999`, `id=abc`)** | Hiển thị khối `.product-not-found`: *"Sản phẩm không tồn tại hoặc đã bị xóa!"* kèm nút về Trang chủ | Hiển thị khối `.product-not-found`: *"Sản phẩm không tồn tại hoặc đã bị xóa!"* kèm nút về Trang chủ |
| **3. Lưu bình luận thất bại (nội dung rỗng / lỗi FK)** | Báo rõ qua `commentError`: *"Nội dung bình luận không được để trống..."* hoặc *"Không thể lưu bình luận..."*; tuyệt đối không báo thành công giả | Báo rõ qua `commentError`: *"Nội dung bình luận không được để trống..."* hoặc *"Không thể lưu bình luận..."*; tuyệt đối không báo thành công giả |
| **4. Dịch vụ CSDL chưa sẵn sàng / Lỗi truy vấn SQL** | Hiển thị `Lỗi CSDL: ...` / `Lỗi truy vấn SQL: ...` kèm `e.getMessage()` (chủ đích phục vụ thực hành Error-based SQLi) | Chỉ hiển thị thông báo chung thân thiện (`AppController.GENERIC_SERVICE_ERROR_MSG`): *"Đã xảy ra lỗi trong quá trình xử lý yêu cầu hoặc dịch vụ tạm thời chưa sẵn sàng. Vui lòng thử lại sau."* Chi tiết lỗi chỉ ghi vào Server Log (`[CORE-07][SECURED][DB_ERROR]`), **không lộ câu lệnh SQL, tên bảng hay Stacktrace** |
| **5. Truy cập đường dẫn không tồn tại (`404`)** | Render trang `templates/error.html` kèm Navbar và trạng thái người dùng hiện tại | Render trang `templates/error.html` kèm Navbar và trạng thái người dùng; cấu hình `server.error.include-message=never`, `include-stacktrace=never` |

---

## 3. Checklist Kiểm thử Luồng Đầy đủ & Minh chứng Nghiệm thu

### 3.1. Bảng Checklist đối chiếu Tiêu chí hoàn thành (`ANM-23` / `CORE-07`)

| Mã test | Tiêu chí hoàn thành & Kịch bản kiểm thử | Phương thức kiểm chứng | Kết quả `app-vulnerable` | Kết quả `app-secured` |
| :---: | :--- | :--- | :---: | :---: |
| **`CORE-07.1`** | Tái sử dụng phần bố cục/thanh điều hướng (`main-navbar`, `labBanner`, `site-footer`) trên tất cả các trang (`/`, `/search`, `/product?id=1`, `/login`) khi chưa đăng nhập. | `Core07NavbarLayoutAndErrorTest#testSharedNavbarAndFooterPresentAcrossAllPagesWhenAnonymous` | **PASS** | **PASS** |
| **`CORE-07.2`** | Hiển thị trạng thái người dùng đã đăng nhập (`Nguyễn Văn A (nguyenvana) (Quyền: customer)`) và nút `Đăng xuất` nhất quán trên Navbar ở mọi trang. | `Core07NavbarLayoutAndErrorTest#testNavbarDisplaysAuthenticatedUserConsistentlyAcrossAllPages` | **PASS** | **PASS** |
| **`CORE-07.3`** | Thông báo rõ khi đăng nhập rỗng/sai mật khẩu, khi xem sản phẩm không tồn tại (`id=999`) và khi lưu bình luận thất bại (nội dung rỗng hoặc sản phẩm không tồn tại). | `Core07NavbarLayoutAndErrorTest#testErrorNotificationsForInvalidLoginNonExistentProductAndInvalidComment` | **PASS** | **PASS** |
| **`CORE-07.4`** | Khi dịch vụ CSDL gặp sự cố (mất bảng/kết nối), hệ thống không sập `500`, hiển thị thông báo dịch vụ rõ ràng; **bản `secured` tuyệt đối không lộ chi tiết SQL hay tên bảng nội bộ**. | `Core07NavbarLayoutAndErrorTest#testDatabaseServiceUnavailable...` | **PASS** | **PASS** |
| **`CORE-07.5`** | Trang lỗi tập trung (`error.html`) bắt lỗi `404 Not Found` thân thiện, tái sử dụng Navbar và giữ nguyên trạng thái phiên đăng nhập của người dùng. | `Core07NavbarLayoutAndErrorTest#testCustomErrorPageRendersFriendlyViewWithNavbarAndSessionState` | **PASS** | **PASS** |
| **`CORE-07.6`** | Chạy thử luồng thương mại điện tử đầy đủ (End-to-End 9 bước): Trang chủ ➔ Tìm kiếm ➔ Chi tiết ➔ Đăng nhập sai ➔ Đăng nhập đúng ➔ Bình luận lỗi ➔ Bình luận hợp lệ ➔ Sản phẩm lỗi ➔ Đăng xuất. | `Core07NavbarLayoutAndErrorTest#testEndToEndEcommerceFlowRunsSeamlessly` | **PASS** | **PASS** |

### 3.2. Checklist Kịch bản Chạy thử Luồng Đầy đủ (End-to-End Flow)

- [x] **Bước 1 (Trang chủ - Khách vãng lai):** Truy cập `GET /` ➔ Hiển thị danh sách 5 sản phẩm mẫu, Navbar hiển thị `Khách vãng lai` và nút `Đăng nhập`.
- [x] **Bước 2 (Tìm kiếm sản phẩm):** Truy cập `GET /search?keyword=Laptop` ➔ Hiển thị sản phẩm *Laptop Dell XPS 15* kèm liên kết `/product?id=3`, mục `Tìm kiếm` sáng `.active` trên Navbar.
- [x] **Bước 3 (Xem chi tiết sản phẩm):** Truy cập `GET /product?id=3` ➔ Hiển thị đúng tên *Laptop Dell XPS 15*, giá `35.000.000 VNĐ`, mục `Chi tiết & Bình luận` sáng `.active` trên Navbar.
- [x] **Bước 4 (Đăng nhập sai thông tin):** Gửi `POST /login` với mật khẩu sai ➔ Hiển thị rõ hộp cảnh báo *"Tên đăng nhập hoặc mật khẩu không chính xác!"*.
- [x] **Bước 5 (Đăng nhập hợp lệ):** Gửi `POST /login` (`nguyenvana` / `pass123456`) ➔ Chuyển hướng thành công, Navbar trên tất cả các trang đồng bộ hiển thị `Nguyễn Văn A (nguyenvana) (Quyền: customer)` và nút `Đăng xuất`.
- [x] **Bước 6 (Gửi bình luận không hợp lệ):** Gửi `POST /product` với nội dung chỉ chứa khoảng trắng ➔ Hệ thống từ chối lưu và hiển thị thông báo lỗi `commentError`.
- [x] **Bước 7 (Gửi bình luận hợp lệ & tải lại trang):** Gửi `POST /product` với nội dung đánh giá hợp lệ ➔ Lưu vào CSDL, hiển thị thông báo `commentSuccess` và hiển thị đúng tác giả `nguyenvana` cùng nội dung bình luận.
- [x] **Bước 8 (Xem sản phẩm không tồn tại & kiểm tra lỗi dịch vụ):** Truy cập `GET /product?id=999` ➔ Hiển thị thông báo *"Sản phẩm không tồn tại hoặc đã bị xóa!"*, vẫn giữ nguyên trạng thái đăng nhập trên Navbar; khi giả lập lỗi CSDL trên `app-secured`, giao diện chỉ hiện thông báo chung thân thiện, không lộ SQL.
- [x] **Bước 9 (Đăng xuất):** Truy cập `GET /logout` ➔ Xóa phiên và cookie, quay về trạng thái `Khách vãng lai`.

### 3.3. Trích xuất Nhật ký Kiểm thử Tự động (`docs/tasks/logs/core-07_test.log`)

Chi tiết toàn bộ log thực thi được lưu tại [`docs/tasks/logs/core-07_test.log`](./logs/core-07_test.log):

```text
# 1. Log kiểm chứng che giấu lỗi SQL nội bộ trên app-secured (CORE-07.4):
ERROR c.uth.websec.controller.AppController : [CORE-07][SECURED][DB_ERROR] Loi truy van danh sach san pham trang chu: Table "products" not found
ERROR c.uth.websec.controller.AppController : [CORE-07][SECURED][DB_ERROR] Tu khoa='iPhone' -> Loi truy van tim kiem: Table "products" not found
ERROR c.uth.websec.controller.AppController : [CORE-07][SECURED][DB_ERROR] Loi truy van chi tiet san pham id='1': Table "products" not found
ERROR c.uth.websec.controller.AppController : [CORE-07][SECURED][DB_ERROR] Loi he thong khi xac thuc dang nhap cho user='nguyenvana': Table "users" not found
--> Phản hồi HTML trên app-secured chỉ hiển thị thông báo chung thân thiện, không lộ từ khóa SQL hay tên bảng.

# 2. Tổng hợp toàn bộ bộ kiểm thử hồi quy từ CORE-03 đến CORE-07 trên cả 2 ứng dụng:
[app-vulnerable] Tests run: 25 (Core04: 5, Core05: 5, Core06: 6, Core07: 6, ModelMapping: 3), Failures: 0, Errors: 0 -> BUILD SUCCESS
[app-secured]    Tests run: 25 (Core04: 5, Core05: 5, Core06: 6, Core07: 6, ModelMapping: 3), Failures: 0, Errors: 0 -> BUILD SUCCESS
```

### 3.4. Hình ảnh Minh chứng Giao diện trên Trình duyệt Demo

1. **Giao diện Trang chủ, Tìm kiếm, Chi tiết & Đăng nhập trên `app-vulnerable` (Cổng `8080`):**
   - [Trang chủ (`01_vulnerable_home_8080.png`)](../screenshots/01_vulnerable_home_8080.png)
   - [Tìm kiếm (`02_vulnerable_search_8080.png`)](../screenshots/02_vulnerable_search_8080.png)
   - [Đăng nhập (`03_vulnerable_login_8080.png`)](../screenshots/03_vulnerable_login_8080.png)
   - [Chi tiết & Bình luận (`04_vulnerable_product_comments_8080.png`)](../screenshots/04_vulnerable_product_comments_8080.png)

2. **Giao diện Trang chủ, Tìm kiếm, Chi tiết & Đăng nhập trên `app-secured` (Cổng `8081`):**
   - [Trang chủ (`05_secured_home_8081.png`)](../screenshots/05_secured_home_8081.png)
   - [Tìm kiếm (`06_secured_search_8081.png`)](../screenshots/06_secured_search_8081.png)
   - [Đăng nhập (`07_secured_login_8081.png`)](../screenshots/07_secured_login_8081.png)
   - [Chi tiết & Bình luận (`08_secured_product_comments_8081.png`)](../screenshots/08_secured_product_comments_8081.png)
