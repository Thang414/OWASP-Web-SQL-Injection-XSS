package com.uth.websec;

import com.uth.websec.config.DbConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * XSS-05 / XSS-06 / XSS-07 / XSS-08 / VERIFY-02 (ANM-42, ANM-43, ANM-44, ANM-45, ANM-47):
 * Kiểm thử mã hóa đầu ra Thymeleaf (kể cả dữ liệu đã lưu trước đó), kiểm tra biên đầu vào,
 * hỗ trợ tiếng Việt Unicode + dấu nháy + ký tự đặc biệt, và kiểm tra CSP/Security Headers.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:sec_xss_defense_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class XssDefenseValidationHeadersTest {

    static final String HARMLESS_SCRIPT = "<script>window.__xss=1</script>";
    static final String HARMLESS_SCRIPT_ENCODED = "&lt;script&gt;window.__xss=1&lt;/script&gt;";
    static final String EXPECTED_CSP = "default-src 'self'; style-src 'self' 'unsafe-inline';";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DbConfig dbConfig;

    @BeforeEach
    void resetSeedDatabase() throws Exception {
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
    @DisplayName("XSS-05 [Output Encoding]: Mã hóa an toàn bình luận Stored XSS đã tồn tại sẵn trong CSDL dùng chung")
    void preExistingStoredXssFromSharedDbIsRenderedEncoded() throws Exception {
        // Giả lập bình luận đã được chèn từ app-vulnerable vào cùng CSDL
        try (Connection conn = dbConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)")) {
            ps.setInt(1, 1);
            ps.setString(2, "<b>Attacker</b>");
            ps.setString(3, HARMLESS_SCRIPT);
            ps.executeUpdate();
        }

        mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;b&gt;Attacker&lt;/b&gt;")))
                .andExpect(content().string(containsString(HARMLESS_SCRIPT_ENCODED)))
                .andExpect(content().string(not(containsString(HARMLESS_SCRIPT))));
    }

    @Test
    @DisplayName("XSS-06 [Boundary & Unicode]: Chấp nhận đúng biên 50/1000 ký tự, tiếng Việt, dấu nháy, ký tự đặc biệt; từ chối vượt biên và ký tự điều khiển")
    void commentValidationBoundariesUnicodeAndControlChars() throws Exception {
        String authorExact50 = "Nguyễn Văn A ".repeat(3) + "12345678901"; // 39 + 11 = 50 chars
        String contentExact1000 = "Đánh giá \"tốt\" & 'rất bền' (5 < 10)! " + "A".repeat(1000 - 37);

        mockMvc.perform(post("/product")
                        .param("product_id", "3")
                        .param("author", authorExact50)
                        .param("content", contentExact1000))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=3"))
                .andExpect(flash().attribute("commentSuccess", "Gửi bình luận đánh giá thành công!"));

        mockMvc.perform(get("/product").param("id", "3"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Đánh giá &quot;tốt&quot; &amp; &#39;rất bền&#39; (5 &lt; 10)!")));

        // Biên vượt chuẩn: author = 51 ký tự
        mockMvc.perform(post("/product")
                        .param("product_id", "3")
                        .param("author", "X".repeat(51))
                        .param("content", "Nội dung hợp lệ"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentError", "Tên người bình luận không được vượt quá 50 ký tự!"));

        // Biên vượt chuẩn: content = 1001 ký tự
        mockMvc.perform(post("/product")
                        .param("product_id", "3")
                        .param("author", "Hợp lệ")
                        .param("content", "Y".repeat(1001)))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentError", "Nội dung bình luận không được vượt quá 1000 ký tự!"));

        // Ký tự điều khiển không hợp lệ (NUL byte) trong content
        mockMvc.perform(post("/product")
                        .param("product_id", "3")
                        .param("author", "Hợp lệ")
                        .param("content", "Xin chào\u0000thế giới"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentError", "Nội dung bình luận chứa ký tự điều khiển không hợp lệ!"));

        // Ký tự xuống dòng trong author bị từ chối
        mockMvc.perform(post("/product")
                        .param("product_id", "3")
                        .param("author", "Tên\nGiả")
                        .param("content", "Nội dung hợp lệ"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentError", "Tên người bình luận chứa ký tự điều khiển không hợp lệ!"));
    }

    @Test
    @DisplayName("XSS-07 [Security Headers]: Kiểm tra đầy đủ CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy trên mọi route chính")
    void securityHeadersPresentAcrossAllMainRoutes() throws Exception {
        String[] routes = {"/", "/login", "/search?keyword=iPhone", "/product?id=1"};
        for (String route : routes) {
            mockMvc.perform(get(route))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Content-Security-Policy", EXPECTED_CSP))
                    .andExpect(header().string("X-Frame-Options", "DENY"))
                    .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                    .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                    .andExpect(header().string("Permissions-Policy", "geolocation=(), microphone=(), camera=()"));
        }
    }

    @Test
    @DisplayName("Regression [HTTP 404/405 & ProductId XSS]: Mã hóa id chứa script và trả lỗi 404/405 an toàn không rò rỉ nội bộ")
    void productIdXssEscapedAndHttp404And405HandledSafely() throws Exception {
        mockMvc.perform(get("/product").param("id", HARMLESS_SCRIPT))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Sản phẩm không tồn tại")))
                .andExpect(content().string(containsString(HARMLESS_SCRIPT_ENCODED)))
                .andExpect(content().string(not(containsString(HARMLESS_SCRIPT))));

        mockMvc.perform(get("/khong-ton-tai-route"))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error"))
                .andExpect(header().string("Content-Security-Policy", EXPECTED_CSP));

        mockMvc.perform(post("/"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(view().name("error"))
                .andExpect(header().string("Content-Security-Policy", EXPECTED_CSP));
    }
}
