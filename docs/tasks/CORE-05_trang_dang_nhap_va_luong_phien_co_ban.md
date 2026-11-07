# Hồ sơ công việc và biên bản nghiệm thu CORE-05 (ANM-21)

## 1. Thông tin công việc

| Thuộc tính | Nội dung chi tiết |
|---|---|
| **Mã nội bộ** | `CORE-05` |
| **Mã trên Jira** | `ANM-21` |
| **Epic** | `EPIC-01 - Phân tích & xây dựng ứng dụng TMĐT` (`ANM-11`) |
| **Phụ trách** | `TV3` - Trần Văn Ngọc Thắng (`tranvanngocthang2006@gmail.com`) |
| **Giai đoạn** | `Sprint 1` (đưa vào `ANM Sprint 2` đang hoạt động trên Jira) |
| **Điểm độ phức tạp (story points)** | `2` |
| **Mức ưu tiên** | `Medium` |
| **Sản phẩm bàn giao** | Trang đăng nhập (`login.html`), luồng xử lý phiên cơ bản (`AppController.java`), bộ kiểm thử tự động (`Core05LoginSessionTest.java`) và biên bản nghiệm thu |
| **Tiêu chí hoàn thành** | Đăng nhập và đăng xuất bằng tài khoản giả lập thành công, duy trì phiên làm việc qua các trang, không dùng tài khoản thật |
| **Phụ thuộc** | `CORE-02` (`ANM-18`), `CORE-03` (`ANM-19`), `INFRA-05` (`ANM-29`) |
| **Giới hạn phạm vi** | Chỉ thao tác trên môi trường lab cục bộ của nhóm với dữ liệu giả lập trong `lab-environment/db/init.sql`; không thử nghiệm trên hệ thống bên ngoài |

## 2. Danh sách tài khoản giả lập sử dụng trong lab

Toàn bộ dữ liệu kiểm thử được khởi tạo từ tệp `lab-environment/db/init.sql` và không chứa bất kỳ thông tin định danh thật nào:

| Tài khoản (`username`) | Mật khẩu (`password`) | Họ và tên (`full_name`) | Quyền (`role`) |
|---|---|---|---|
| **nguyenvana** | `pass123456` | Nguyễn Văn A | `customer` |
| **tranthib** | `passwordB123` | Trần Thị B | `customer` |
| **manager** | `manager@2026` | Trưởng Phòng Kinh Doanh | `manager` |
| **admin** | `admin123_super_secret` | Quản Trị Viên Hệ Thống | `admin` |

## 3. Các thành phần đã triển khai

- **Giao diện đăng nhập (`login.html`):** xây dựng biểu mẫu đăng nhập tại cả hai ứng dụng (`app-vulnerable` và `app-secured`), hiển thị thông báo lỗi khi xác thực thất bại, thông báo khi vừa đăng xuất, trạng thái phiên đang hoạt động và bảng tra cứu nhanh 4 tài khoản giả lập trong `init.sql`.
- **Xử lý xác thực và quản lý phiên (`AppController.java`):**
  - Xử lý `GET /login` (và `/login.php`), `POST /login` (và `/login.php`), `GET /logout` (và `/logout.php`).
  - Lưu đối tượng `User` vào `HttpSession` (`session.setAttribute("user", user)`) và đồng bộ cookie `session_token` khi đăng nhập thành công.
  - Ở bản chứa lỗ hổng (`app-vulnerable`, cổng `8080`): giữ nguyên truy vấn nối chuỗi để phục vụ kịch bản minh họa vượt qua xác thực bằng tiêm mã truy vấn có cấu trúc (`SQL Injection Authentication Bypass`) và đặt `HttpOnly=false` cho cookie `session_token` để phục vụ kịch bản đánh cắp phiên qua kịch bản chèn mã liên trang lưu trữ (`Stored XSS`).
  - Ở bản đã vá (`app-secured`, cổng `8081`): sử dụng truy vấn tham số hóa (`PreparedStatement`) chống tiêm mã truy vấn và thiết lập `ResponseCookie` với cờ `HttpOnly=true`, `SameSite=Strict` cho `session_token`.
  - Hỗ trợ khôi phục thông tin người dùng từ `HttpSession` hoặc cookie `session_token` hợp lệ qua phương thức `resolveSessionUser`, đồng thời hủy toàn bộ `HttpSession` (`session.invalidate()`) và xóa cookie `session_token` (`Max-Age=0`) khi người dùng đăng xuất.
- **Hiển thị phiên nhất quán trên toàn bộ giao diện (`index.html`, `search.html`, `product.html`):** bổ sung khối hiển thị trạng thái người dùng (`Xin chào, <Họ tên> (<username>) (Quyền: <role>) | Đăng xuất` hoặc nút `Đăng nhập`) trên thanh điều hướng của trang chủ, trang tìm kiếm và trang chi tiết sản phẩm ở cả hai ứng dụng.

## 4. Danh sách kiểm tra nghiệm thu thực tế

| Mã kịch bản | Nội dung kiểm tra | Kết quả trên `app-vulnerable` | Kết quả trên `app-secured` |
|---|---|---|---|
| **AC-01** | Đăng nhập đúng tài khoản giả lập (`nguyenvana` / `pass123456`, `admin` / `admin123_super_secret`): chuyển hướng `302` về `/index.php`, hiển thị đúng họ tên, tên đăng nhập và quyền người dùng | Đạt (`PASS`) | Đạt (`PASS`) |
| **AC-02** | Đăng nhập sai mật khẩu (`nguyenvana` / `sai_mat_khau_123`): hiển thị thông báo `"Tên đăng nhập hoặc mật khẩu không chính xác!"`, không tạo trạng thái đăng nhập trong `HttpSession` | Đạt (`PASS`) | Đạt (`PASS`) |
| **AC-03** | Duy trì phiên khi tải lại trang chủ (`/`), chuyển sang trang tìm kiếm (`/search?keyword=iPhone`) và trang chi tiết sản phẩm (`/product?id=1`): giữ nguyên thông tin người dùng và quyền trong cùng phiên | Đạt (`PASS`) | Đạt (`PASS`) |
| **AC-04** | Đăng xuất (`GET /logout`): hủy `HttpSession`, đặt `Max-Age=0` xóa cookie `session_token`, tải lại trang chủ trở về trạng thái chưa đăng nhập | Đạt (`PASS`) | Đạt (`PASS`) |
| **AC-05** | Tuân thủ giới hạn an toàn: chỉ sử dụng dữ liệu giả lập từ `lab-environment/db/init.sql`, không dùng tài khoản thật, không tương tác với hệ thống bên ngoài | Đạt (`PASS`) | Đạt (`PASS`) |
