package com.uth.websec;

import com.uth.websec.config.DbConfig;
import com.uth.websec.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import jakarta.servlet.http.Cookie;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:secured_core05_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class Core05LoginSessionTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DbConfig dbConfig;

    @BeforeEach
    void setUpSeedDatabase() throws Exception {
        Path initSqlPath = Path.of("../db/init.sql");
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
    @DisplayName("CORE-05.1: Trang đăng nhập bảo mật hiển thị biểu mẫu và danh sách tài khoản giả lập từ init.sql")
    void testLoginPageDisplaysMockSeedAccounts() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("nguyenvana")))
                .andExpect(content().string(containsString("pass123456")))
                .andExpect(content().string(containsString("admin123_super_secret")))
                .andExpect(content().string(containsString("không dùng tài khoản thật")));
    }

    @Test
    @DisplayName("CORE-05.2: Đăng nhập đúng tài khoản giả lập chuyển về trang chủ, đổi mã phiên và hiển thị đúng tên/quyền")
    void testValidLoginWithMockAccountRedirectsToHomeAndDisplaysUserRole() throws Exception {
        MockHttpSession session = new MockHttpSession();

        String anonymousSessionId = session.getId();
        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456")
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"))
                .andReturn();

        User loggedInUser = (User) session.getAttribute("user");
        assertThat(loggedInUser).isNotNull();
        assertThat(loggedInUser.getUsername()).isEqualTo("nguyenvana");
        assertThat(loggedInUser.getFullName()).isEqualTo("Nguyễn Văn A");
        assertThat(loggedInUser.getRole()).isEqualTo("customer");

        assertThat(session.getId()).isNotEqualTo(anonymousSessionId);

        mockMvc.perform(get("/index.php").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(content().string(containsString("Nguyễn Văn A (nguyenvana) (Quyền: customer)")))
                .andExpect(content().string(containsString("Đăng xuất")));
    }

    @Test
    @DisplayName("CORE-05.3: Đăng nhập sai mật khẩu hoặc payload SQLi hiển thị thông báo thất bại và không tạo phiên")
    void testInvalidLoginShowsErrorMessageAndDoesNotCreateSession() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "sai_mat_khau_123")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!"))
                .andExpect(content().string(containsString("Tên đăng nhập hoặc mật khẩu không chính xác!")));

        assertThat(session.getAttribute("user")).isNull();

        // Kiểm chứng payload SQLi Authentication Bypass cũng bị chặn hoàn toàn trên app-secured
        mockMvc.perform(post("/login")
                        .param("username", "admin' -- ")
                        .param("password", "anything")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!"));

        assertThat(session.getAttribute("user")).isNull();
    }

    @Test
    @DisplayName("CORE-05.4: Duy trì phiên khi tải lại trang chủ, chuyển qua trang tìm kiếm và chi tiết sản phẩm")
    void testSessionPersistsAcrossReloadSearchAndProductDetail() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(post("/login")
                        .param("username", "admin")
                        .param("password", "admin123_super_secret")
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"));

        String expectedBanner = "Quản Trị Viên Hệ Thống (admin) (Quyền: admin)";

        // 1. Tải lại trang chủ
        mockMvc.perform(get("/").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedBanner)))
                .andExpect(content().string(containsString("Đăng xuất")));

        // 2. Chuyển qua trang tìm kiếm
        mockMvc.perform(get("/search").param("keyword", "iPhone").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedBanner)))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")))
                .andExpect(content().string(containsString("Đăng xuất")));

        // 3. Chuyển qua trang chi tiết sản phẩm
        mockMvc.perform(get("/product").param("id", "1").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedBanner)))
                .andExpect(content().string(containsString("value=\"admin\"")))
                .andExpect(content().string(containsString("Đăng xuất")));
    }

    @Test
    @DisplayName("CORE-05.5: Đăng xuất hủy HttpSession và đưa trang chủ về trạng thái chưa đăng nhập")
    void testLogoutInvalidatesHttpSessionClearsCookieAndResetsHomeState() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456")
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"));

        assertThat(session.getAttribute("user")).isNotNull();

        mockMvc.perform(get("/logout").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login.php"))
                .andReturn();

        assertThat(session.isInvalid()).isTrue();

        // Tải lại trang chủ sau khi đăng xuất
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Đăng nhập")))
                .andExpect(content().string(not(containsString("Nguyễn Văn A (nguyenvana)"))));
    }

    @Test
    void forgedLegacyCookieDoesNotAuthenticate() throws Exception {
        String forged = java.util.Base64.getEncoder().encodeToString(
                "admin_secured_token_8081".getBytes(StandardCharsets.UTF_8));
        MockHttpSession session = new MockHttpSession();
        mockMvc.perform(get("/").session(session).cookie(new Cookie("session_token", forged)))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("(Quyền: admin)"))));
        assertThat(session.getAttribute("user")).isNull();
    }
}
