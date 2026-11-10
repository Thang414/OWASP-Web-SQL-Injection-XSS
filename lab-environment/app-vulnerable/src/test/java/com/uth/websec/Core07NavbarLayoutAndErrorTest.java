package com.uth.websec;

import com.uth.websec.config.DbConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:vuln_core07_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class Core07NavbarLayoutAndErrorTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DbConfig dbConfig;

    @BeforeEach
    void setUpSeedDatabase() throws Exception {
        Path initSqlPath = Path.of("../db/init.sql");
        if (!Files.exists(initSqlPath)) {
            initSqlPath = Path.of("lab-environment/db/init.sql");
        }
        String rawSql = Files.readString(initSqlPath, StandardCharsets.UTF_8);

        StringBuilder cleanedSql = new StringBuilder();
        for (String line : rawSql.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("--")) {
                continue;
            }
            String upper = trimmed.toUpperCase();
            if (upper.startsWith("CREATE DATABASE") || upper.startsWith("USE ")) {
                continue;
            }
            cleanedSql.append(line).append("\n");
        }

        try (Connection conn = dbConfig.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP TABLE IF EXISTS comments");
            stmt.execute("DROP TABLE IF EXISTS products");
            stmt.execute("DROP TABLE IF EXISTS users");
            for (String statement : cleanedSql.toString().split(";")) {
                String sql = statement.trim();
                if (!sql.isEmpty()) {
                    stmt.execute(sql);
                }
            }
        }
    }

    @Test
    @DisplayName("CORE-07.1: Tái sử dụng Navbar, Lab Banner và Footer dùng chung trên mọi trang khi chưa đăng nhập")
    void testSharedNavbarAndFooterPresentAcrossAllPagesWhenAnonymous() throws Exception {
        String[] endpoints = {"/", "/search", "/product?id=1", "/login"};

        for (String endpoint : endpoints) {
            mockMvc.perform(get(endpoint))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("class=\"main-navbar\"")))
                    .andExpect(content().string(containsString("VULNERABLE LAB :8080")))
                    .andExpect(content().string(containsString("href=\"/\"")))
                    .andExpect(content().string(containsString("href=\"/search\"")))
                    .andExpect(content().string(containsString("href=\"/product?id=1\"")))
                    .andExpect(content().string(containsString("Khách vãng lai")))
                    .andExpect(content().string(containsString("Đăng nhập")))
                    .andExpect(content().string(containsString("class=\"site-footer\"")));
        }
    }

    @Test
    @DisplayName("CORE-07.2: Hiển thị trạng thái người dùng đã đăng nhập nhất quán trên Navbar ở tất cả các trang")
    void testNavbarDisplaysAuthenticatedUserConsistentlyAcrossAllPages() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456")
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"));

        String expectedUserBanner = "Nguyễn Văn A (nguyenvana) (Quyền: customer)";
        String[] endpoints = {"/", "/search?keyword=iPhone", "/product?id=1", "/login"};

        for (String endpoint : endpoints) {
            mockMvc.perform(get(endpoint).session(session))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("class=\"main-navbar\"")))
                    .andExpect(content().string(containsString(expectedUserBanner)))
                    .andExpect(content().string(containsString("href=\"/logout\"")))
                    .andExpect(content().string(containsString("Đăng xuất")));
        }
    }

    @Test
    @DisplayName("CORE-07.3: Thông báo rõ ràng khi đăng nhập sai/rỗng, sản phẩm không tồn tại và lưu bình luận thất bại")
    void testErrorNotificationsForInvalidLoginNonExistentProductAndInvalidComment() throws Exception {
        // 1. Đăng nhập với tài khoản rỗng
        mockMvc.perform(post("/login")
                        .param("username", "   ")
                        .param("password", ""))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("Vui lòng nhập tên đăng nhập!")));

        // 2. Đăng nhập sai mật khẩu
        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "wrong_pass"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("Tên đăng nhập hoặc mật khẩu không chính xác!")));

        // 3. Sản phẩm không tồn tại (id=999)
        mockMvc.perform(get("/product").param("id", "999"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("Sản phẩm không tồn tại hoặc đã bị xóa!")));

        // 4. Lưu bình luận thất bại (nội dung rỗng & sản phẩm không tồn tại)
        mockMvc.perform(post("/product")
                        .param("product_id", "1")
                        .param("author", "Hồng Sơn")
                        .param("content", "   "))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentError", "Nội dung bình luận không được để trống hoặc chỉ chứa khoảng trắng!"));

        mockMvc.perform(post("/product")
                        .param("product_id", "999")
                        .param("author", "Hồng Sơn")
                        .param("content", "Bình luận vào sản phẩm không tồn tại"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentError", "Không thể lưu bình luận: Sản phẩm không tồn tại hoặc dữ liệu không hợp lệ!"))
                .andExpect(flash().attribute("commentSuccess", (Object) null));
    }

    @Test
    @DisplayName("CORE-07.4: Khi dịch vụ CSDL gặp sự cố, hệ thống không sập 500 và hiển thị cảnh báo lỗi trên giao diện")
    void testDatabaseServiceUnavailableShowsErrorBannerWithoutCrashing() throws Exception {
        // Giả lập sự cố mất bảng CSDL
        try (Connection conn = dbConfig.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP TABLE IF EXISTS comments");
            stmt.execute("DROP TABLE IF EXISTS products");
            stmt.execute("DROP TABLE IF EXISTS users");
        }

        // Trang chủ vẫn trả về HTTP 200 kèm khối global-service-error và Navbar
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(content().string(containsString("class=\"main-navbar\"")))
                .andExpect(content().string(containsString("global-service-error")))
                .andExpect(content().string(containsString("Lỗi CSDL:")));

        // Trang chi tiết vẫn trả về HTTP 200 kèm khối global-service-error
        mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("global-service-error")))
                .andExpect(content().string(containsString("Lỗi CSDL:")));

        // Trang đăng nhập xử lý lỗi CSDL mà không sập
        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("Lỗi truy vấn SQL:")));
    }

    @Test
    @DisplayName("CORE-07.5: Trang báo lỗi tập trung (error.html) hiển thị thân thiện kèm Navbar giữ nguyên trạng thái phiên")
    void testCustomErrorPageRendersFriendlyViewWithNavbarAndSessionState() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456")
                        .session(session))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/duong-dan-khong-ton-tai-404").session(session))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error"))
                .andExpect(content().string(containsString("class=\"main-navbar\"")))
                .andExpect(content().string(containsString("Nguyễn Văn A (nguyenvana) (Quyền: customer)")))
                .andExpect(content().string(containsString("Không tìm thấy trang yêu cầu (404)")))
                .andExpect(content().string(containsString("Quay về Trang chủ")));
    }

    @Test
    @DisplayName("CORE-07.6: Chạy thử luồng thương mại điện tử đầy đủ (End-to-End) liền mạch")
    void testEndToEndEcommerceFlowRunsSeamlessly() throws Exception {
        MockHttpSession session = new MockHttpSession();

        // Bước 1: Khách vãng lai vào Trang chủ
        mockMvc.perform(get("/").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Khách vãng lai")))
                .andExpect(content().string(containsString("Laptop Dell XPS 15")));

        // Bước 2: Tìm kiếm sản phẩm "Laptop"
        mockMvc.perform(get("/search").param("keyword", "Laptop").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Laptop Dell XPS 15")))
                .andExpect(content().string(containsString("/product?id=3")));

        // Bước 3: Xem chi tiết sản phẩm ID=3
        mockMvc.perform(get("/product").param("id", "3").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Laptop Dell XPS 15")))
                .andExpect(content().string(containsString("35.000.000 VNĐ")))
                .andExpect(content().string(containsString("Chưa có bình luận nào cho sản phẩm này.")));

        // Bước 4: Đăng nhập sai mật khẩu -> Nhận thông báo lỗi rõ ràng
        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "sai_mat_khau")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Tên đăng nhập hoặc mật khẩu không chính xác!")));

        // Bước 5: Đăng nhập đúng tài khoản nguyenvana
        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456")
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"));

        // Bước 6: Gửi bình luận rỗng tại sản phẩm ID=3 -> Nhận thông báo lỗi commentError
        mockMvc.perform(post("/product")
                        .param("product_id", "3")
                        .param("author", "")
                        .param("content", "   ")
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=3"))
                .andExpect(flash().attribute("commentError", "Nội dung bình luận không được để trống hoặc chỉ chứa khoảng trắng!"));

        // Bước 7: Gửi bình luận hợp lệ tại sản phẩm ID=3 và tải lại trang
        String e2eComment = "Trải nghiệm luồng End-to-End CORE-07 hoạt động mượt mà!";
        mockMvc.perform(post("/product")
                        .param("product_id", "3")
                        .param("author", "")
                        .param("content", e2eComment)
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=3"))
                .andExpect(flash().attribute("commentSuccess", "Gửi bình luận đánh giá thành công!"));

        mockMvc.perform(get("/product").param("id", "3").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Nguyễn Văn A (nguyenvana) (Quyền: customer)")))
                .andExpect(content().string(containsString("nguyenvana")))
                .andExpect(content().string(containsString(e2eComment)));

        // Bước 8: Truy cập sản phẩm không tồn tại (id=999) -> Nhận thông báo lỗi nhưng vẫn giữ phiên đăng nhập trên Navbar
        mockMvc.perform(get("/product").param("id", "999").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Sản phẩm không tồn tại hoặc đã bị xóa!")))
                .andExpect(content().string(containsString("Nguyễn Văn A (nguyenvana) (Quyền: customer)")));

        // Bước 9: Đăng xuất và kiểm tra trạng thái quay về Khách vãng lai
        mockMvc.perform(get("/logout").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login.php"));

        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Khách vãng lai")))
                .andExpect(content().string(not(containsString("Nguyễn Văn A (nguyenvana)"))));
    }
}
