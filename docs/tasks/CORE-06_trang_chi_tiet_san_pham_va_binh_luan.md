# BIÊN BẢN NGHIỆM THU TASK CORE-06 (ANM-22)
**Tạo trang chi tiết sản phẩm và khu vực bình luận**

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Mã nội bộ** | `CORE-06` (`ANM-22`) |
| **Phạm vi phụ trách** | TV2 - Hồng Sơn |
| **Ưu tiên kế hoạch** | Cao |
| **Phụ thuộc** | [ANM-18 (`CORE-02`)](./CORE-02_dung_khung_ung_dung_baseline_va_secured.md), [ANM-19 (`CORE-03`)](./CORE-03_thiet_ke_model_va_anh_xa_du_lieu.md), [ANM-29 (`INFRA-05`)](./INFRA-05_kiem_chung_khoi_dong_stack_va_health_check.md) |
| **Trạng thái** | **HOÀN THÀNH (DONE)** |

> **Theo dõi kế hoạch & Giới hạn an toàn:**
> - Sprint, điểm ước lượng và người được giao được quản lý trực tiếp bằng trường Jira; không sao chép số sprint hoặc điểm vào mô tả.
> - Chỉ thực hiện trên lab của nhóm (`localhost`) và bộ dữ liệu giả trong [`lab-environment/db/init.sql`](../../lab-environment/db/init.sql); tuyệt đối không thử nghiệm hệ thống bên ngoài và không thu thập tài khoản hay thông tin cá nhân thật.

---

## 1. Mục tiêu & Sản phẩm bàn giao (Deliverables)

Hoàn thiện chức năng xem chi tiết sản phẩm và gửi, lưu, hiển thị bình luận ở cả hai ứng dụng (`app-vulnerable` và `app-secured`), đảm bảo kiểm soát đầu vào hợp lệ, không báo thành công giả khi lưu thất bại, và thể hiện rõ sự khác biệt về cơ chế phòng thủ Stored XSS giữa hai phiên bản.

| Hạng mục bàn giao | Tệp tin / Đường dẫn trong Repository | Mô tả |
| :--- | :--- | :--- |
| **Xử lý phía máy chủ (Vulnerable)** | [`lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/AppController.java`](../../lab-environment/app-vulnerable/src/main/java/com/uth/websec/controller/AppController.java) | Endpoint `GET /product`, `GET /products/{id}` và `POST /product` với kiểm tra đầu vào, kiểm tra `rowsAffected > 0`, ghi log `[CORE-06][READ]` / `[CORE-06][WRITE]` và giữ nguyên truy vấn nối chuỗi phục vụ Lab SQLi & Stored XSS |
| **Xử lý phía máy chủ (Secured)** | [`lab-environment/app-secured/src/main/java/com/uth/websec/controller/AppController.java`](../../lab-environment/app-secured/src/main/java/com/uth/websec/controller/AppController.java) | Endpoint `GET /product`, `GET /products/{id}` và `POST /product` sử dụng `PreparedStatement`, ép kiểu `Integer.parseInt`, kiểm tra đầu vào, kiểm tra `rowsAffected > 0` và ghi log `[CORE-06][READ]` / `[CORE-06][WRITE]` |
| **Giao diện Chi tiết & Bình luận (Vulnerable)** | [`lab-environment/app-vulnerable/src/main/resources/templates/product.html`](../../lab-environment/app-vulnerable/src/main/resources/templates/product.html) | Trang chi tiết sản phẩm, thông báo sản phẩm không tồn tại (`product == null`), hộp thông báo `commentSuccess`/`commentError` và hiển thị bình luận bằng `th:utext="${c.content}"` (Unescaped HTML) |
| **Giao diện Chi tiết & Bình luận (Secured)** | [`lab-environment/app-secured/src/main/resources/templates/product.html`](../../lab-environment/app-secured/src/main/resources/templates/product.html) | Trang chi tiết sản phẩm, thông báo sản phẩm không tồn tại (`product == null`), hộp thông báo `commentSuccess`/`commentError` và hiển thị bình luận an toàn bằng `th:text="${c.content}"` (HTML Entity Encoding) |
| **Bộ kiểm thử tự động (Vulnerable)** | [`lab-environment/app-vulnerable/src/test/java/com/uth/websec/Core06ProductDetailAndCommentTest.java`](../../lab-environment/app-vulnerable/src/test/java/com/uth/websec/Core06ProductDetailAndCommentTest.java) | 6 bài kiểm thử tích hợp JUnit 5 + Spring `MockMvc` (`CORE-06.1` → `CORE-06.6`) cho `app-vulnerable` |
| **Bộ kiểm thử tự động (Secured)** | [`lab-environment/app-secured/src/test/java/com/uth/websec/Core06ProductDetailAndCommentTest.java`](../../lab-environment/app-secured/src/test/java/com/uth/websec/Core06ProductDetailAndCommentTest.java) | 6 bài kiểm thử tích hợp JUnit 5 + Spring `MockMvc` (`CORE-06.1` → `CORE-06.6`) cho `app-secured` |
| **Log kiểm thử từng trường hợp** | [`docs/tasks/logs/core-06_test.log`](./logs/core-06_test.log) | Nhật ký chạy `mvn test` (`19/19 PASS` mỗi bản) và log đối chiếu luồng đọc/ghi chi tiết sản phẩm & bình luận |
| **Ảnh chụp màn hình minh chứng** | [`04_vulnerable_product_comments_8080.png`](../screenshots/04_vulnerable_product_comments_8080.png), [`08_secured_product_comments_8081.png`](../screenshots/08_secured_product_comments_8081.png) | Ảnh chụp giao diện trang chi tiết sản phẩm và khu vực bình luận thực tế trên hai cổng `8080` và `8081` |

---

## 2. Thiết kế & Hành vi Xử lý Phía Máy chủ (Server-side Behavior)

### 2.1. Luồng đọc chi tiết sản phẩm và danh sách bình luận (`GET /product`, `GET /products/{id}`)
1. **Sản phẩm hợp lệ tồn tại trong CSDL (ví dụ `id=1` - *iPhone 15 Pro Max*):**
   - Hiển thị đầy đủ tên sản phẩm, danh mục (`Điện thoại`), mô tả chi tiết, ảnh minh họa (`product.imageUrl`) và giá tiền định dạng chuẩn (`29.990.000 VNĐ`).
   - Truy vấn danh sách bình luận của sản phẩm theo thứ tự mới nhất trước (`ORDER BY id DESC`), hiển thị tên tác giả (`c.author`), thời gian đăng (`c.createdAt`) và nội dung (`c.content`).
   - Nếu sản phẩm chưa có bình luận nào (ví dụ `id=3` - *Laptop Dell XPS 15*), hiển thị thông báo: *"Chưa có bình luận nào cho sản phẩm này."*
2. **Sản phẩm không tồn tại (`id=999`) hoặc tham số `id` sai định dạng (`id=invalid_id`):**
   - Máy chủ xử lý ngoại lệ an toàn, không làm sập trang (luôn trả về HTTP `200 OK`), đặt `product = null`.
   - Giao diện `product.html` hiển thị khối `.product-not-found` với thông báo thân thiện: *"Sản phẩm không tồn tại hoặc đã bị xóa!"* kèm nút điều hướng quay lại Trang chủ (`/`).

### 2.2. Luồng gửi và lưu bình luận (`POST /product`)
1. **Kiểm tra tính hợp lệ của đầu vào (Input Validation):**
   - **Mã sản phẩm rỗng (`product_id` trống):** Từ chối lưu, gán Flash Attribute `commentError = "Mã sản phẩm không hợp lệ!"` và chuyển hướng về `/`.
   - **Nội dung bình luận rỗng hoặc chỉ chứa khoảng trắng (`content.trim().isEmpty()`):** Từ chối lưu vào CSDL, gán Flash Attribute `commentError = "Nội dung bình luận không được để trống hoặc chỉ chứa khoảng trắng!"` và chuyển hướng về `/product?id={productId}`.
   - **Tên người gửi vượt quá 50 ký tự (`author.trim().length() > 50`):** Từ chối lưu, gán Flash Attribute `commentError = "Tên người bình luận không được vượt quá 50 ký tự!"`.
   - **Nội dung vượt quá 1000 ký tự (`content.trim().length() > 1000`):** Từ chối lưu, gán Flash Attribute `commentError = "Nội dung bình luận không được vượt quá 1000 ký tự!"`.
   - **Tự động nhận diện tác giả:** Nếu `author` để trống, hệ thống tự động lấy `username` từ phiên đăng nhập hiện tại (`HttpSession`) hoặc gán mặc định `"Khách hàng"`.
2. **Lưu CSDL và chống báo thành công giả (No False-Positive Success):**
   - Chỉ khi câu lệnh `INSERT INTO comments` thực thi thành công và trả về `rowsAffected > 0`, hệ thống mới gán Flash Attribute `commentSuccess = "Gửi bình luận đánh giá thành công!"`.
   - Nếu câu lệnh `INSERT` thất bại (ví dụ `product_id=999` vi phạm ràng buộc khóa ngoại `FOREIGN KEY` hoặc lỗi kết nối CSDL), khối `catch` ghi nhận log `[CORE-06][WRITE][DB_ERROR]`, giữ `commentSuccess = null` và gán `commentError = "Không thể lưu bình luận: Sản phẩm không tồn tại hoặc dữ liệu không hợp lệ!"`.

### 2.3. Khác biệt bảo vệ Stored XSS giữa hai ứng dụng (Kiểm chứng cùng nhóm XSS)

| Tiêu chí đối chiếu | Bản dễ tổn thương (`app-vulnerable` - Cổng `8080`) | Bản vá bảo mật (`app-secured` - Cổng `8081`) |
| :--- | :--- | :--- |
| **Cơ chế lưu bình luận (`POST /product`)** | Dùng `Statement` nối chuỗi trực tiếp `INSERT INTO comments ...` (phục vụ Lab SQLi & Stored XSS) | Dùng `PreparedStatement` tham số hóa `INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)` |
| **Cơ chế hiển thị nội dung (`product.html`)** | `<div class="comment-body" th:utext="${c.content}"></div>` (**Unescaped HTML** - trình duyệt thực thi trực tiếp thẻ `<script>` trong bình luận) | `<div class="comment-body" th:text="${c.content}"></div>` (**HTML Entity Encoding** - tự động mã hóa `<script>` thành `&lt;script&gt;` hiển thị dưới dạng văn bản thuần) |
| **Lớp phòng thủ bổ sung trên HTTP Header** | Không áp dụng CSP | Áp dụng `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline';` và `X-Content-Type-Options: nosniff` |

---

## 3. Minh chứng Nghiệm thu (Acceptance Evidence)

### 3.1. Bảng Checklist đối chiếu Tiêu chí hoàn thành

| Mã test | Tiêu chí hoàn thành (Jira `ANM-22` / `CORE-06`) | Phương thức kiểm chứng | Kết quả `app-vulnerable` | Kết quả `app-secured` |
| :---: | :--- | :--- | :---: | :---: |
| **`CORE-06.1`** | Xem đúng thông tin, giá (`29.990.000 VNĐ`) và bình luận của sản phẩm mẫu (`id=1`, `id=3`). | `Core06ProductDetailAndCommentTest#testViewValidProductDisplaysInfoPriceAndComments` | **PASS** | **PASS** |
| **`CORE-06.2`** | Sản phẩm không tồn tại (`id=999`) hoặc ID không hợp lệ (`id=invalid_id`) có thông báo phù hợp, không lỗi 500. | `Core06ProductDetailAndCommentTest#testViewNonExistentOrInvalidProductShowsFriendlyMessage` | **PASS** | **PASS** |
| **`CORE-06.3`** | Gửi bình luận hợp lệ, lưu vào cơ sở dữ liệu, tải lại vẫn thấy đúng sản phẩm, tác giả (`Hồng Sơn`) và nội dung. | `Core06ProductDetailAndCommentTest#testSubmitValidCommentPersistsAndDisplaysAfterReload` | **PASS** | **PASS** |
| **`CORE-06.4`** | Nội dung rỗng (`""`) hoặc chỉ chứa khoảng trắng (`"   \t\n  "`) được xử lý có thông báo lỗi (`commentError`). | `Core06ProductDetailAndCommentTest#testSubmitEmptyOrWhitespaceCommentIsRejectedWithMessage` | **PASS** | **PASS** |
| **`CORE-06.5`** | Đầu vào không hợp lệ (`author > 50` ký tự, `content > 1000` ký tự) bị từ chối kèm thông báo lỗi, không lưu vào CSDL. | `Core06ProductDetailAndCommentTest#testSubmitOverlongAuthorOrContentIsRejectedWithMessage` | **PASS** | **PASS** |
| **`CORE-06.6`** | Không báo thành công giả khi lưu thất bại (`product_id=999` vi phạm khóa ngoại CSDL -> `commentSuccess == null`). | `Core06ProductDetailAndCommentTest#testNoFalsePositiveSuccessWhenDatabaseInsertFails` | **PASS** | **PASS** |

### 3.2. Trích xuất Log Kiểm thử luồng Đọc và Ghi (`docs/tasks/logs/core-06_test.log`)

Chi tiết toàn bộ nhật ký thực thi được lưu tại [`docs/tasks/logs/core-06_test.log`](./logs/core-06_test.log). Trích xuất log minh chứng các trường hợp đọc/ghi trên cả 2 ứng dụng:

```text
# 1. Luồng đọc sản phẩm tồn tại (id=1, id=3) và không tồn tại (id=999, id=invalid_id):
INFO  c.uth.websec.controller.AppController : [CORE-06][READ][FOUND] Xem chi tiet san pham (vulnerable) id='1' (name='iPhone 15 Pro Max') - So binh luan hien co: 2
INFO  c.uth.websec.controller.AppController : [CORE-06][READ][FOUND] Xem chi tiet san pham (vulnerable) id='3' (name='Laptop Dell XPS 15') - So binh luan hien co: 0
WARN  c.uth.websec.controller.AppController : [CORE-06][READ][NOT_FOUND] San pham khong ton tai (vulnerable): id='999'
WARN  c.uth.websec.controller.AppController : [CORE-06][READ][NOT_FOUND] San pham khong ton tai hoac ID khong hop le (secured): id='invalid_id'

# 2. Luồng từ chối bình luận rỗng / vượt quá độ dài và chống báo thành công giả khi lỗi DB:
WARN  c.uth.websec.controller.AppController : [CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='1' - Noi dung rong hoac chi chua khoang trang
WARN  c.uth.websec.controller.AppController : [CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='1' - Ten tac gia vuot qua 50 ky tu (len=55)
WARN  c.uth.websec.controller.AppController : [CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='1' - Noi dung vuot qua 1000 ky tu (len=1005)
ERROR c.uth.websec.controller.AppController : [CORE-06][WRITE][DB_ERROR] Luu binh luan that bai cho product_id='999' - Loi DB: Referential integrity constraint violation

# 3. Luồng gửi bình luận hợp lệ, lưu CSDL và tải lại trang thấy bình luận mới (tăng từ 2 -> 3):
INFO  c.uth.websec.controller.AppController : [CORE-06][WRITE][REQUEST] Nhan yeu cau gui binh luan (secured): product_id='1', author='Hồng Sơn'
INFO  c.uth.websec.controller.AppController : [CORE-06][WRITE][SAVED] Luu binh luan thanh cong vao DB (secured): product_id='1', author='Hồng Sơn', rowsAffected=1
INFO  c.uth.websec.controller.AppController : [CORE-06][READ][FOUND] Xem chi tiet san pham (secured) id='1' (name='iPhone 15 Pro Max') - So binh luan hien co: 3

# 4. Tổng hợp kết quả chạy bộ test tự động trên cả hai ứng dụng:
[app-vulnerable] Tests run: 19, Failures: 0, Errors: 0, Skipped: 0 -> BUILD SUCCESS
[app-secured]    Tests run: 19, Failures: 0, Errors: 0, Skipped: 0 -> BUILD SUCCESS
```

### 3.3. Hình ảnh Minh chứng Giao diện trên 2 Phiên bản

1. **Trang chi tiết sản phẩm & khu vực bình luận trên `app-vulnerable` (`http://localhost:8080/product?id=1`):**
   ![Chi tiết sản phẩm & Bình luận Vulnerable](../screenshots/04_vulnerable_product_comments_8080.png)

2. **Trang chi tiết sản phẩm & khu vực bình luận trên `app-secured` (`http://localhost:8081/product?id=1`):**
   ![Chi tiết sản phẩm & Bình luận Secured](../screenshots/08_secured_product_comments_8081.png)
