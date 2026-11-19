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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * SQLI-05 / SQLI-06 / SQLI-07 / VERIFY-01 (ANM-35, ANM-36, ANM-37, ANM-46):
 * Xác minh toàn bộ truy vấn đăng nhập, tìm kiếm, chi tiết sản phẩm và bình luận trên app-secured
 * chặn triệt để SQL Injection trong khi vẫn giữ nguyên chức năng hợp lệ.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:sec_sqli_defense_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class SqliDefenseAndRegressionTest {

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

    private int countCommentsForProduct(int productId) throws Exception {
        try (Connection conn = dbConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM comments WHERE product_id = ?")) {
            ps.setInt(1, productId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    @Test
    @DisplayName("SQLI-05 [Login]: Chặn toàn bộ payload Auth Bypass và vẫn cho phép đăng nhập hợp lệ")
    void loginBlocksAllAuthBypassPayloadsAndPreservesValidLogin() throws Exception {
        String[][] attackPayloads = {
                {"admin' -- ", "wrong_pass"},
                {"' OR 1=1 -- ", "anything"},
                {"admin' or '1'='1", "' or '1'='1"},
                {"admin'/*", "*/ OR 1=1 -- "}
        };

        for (String[] pair : attackPayloads) {
            MockHttpSession session = new MockHttpSession();
            mockMvc.perform(post("/login")
                            .param("username", pair[0])
                            .param("password", pair[1])
                            .session(session))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!"));
            assertThat(session.getAttribute("user")).isNull();
        }

        MockHttpSession validSession = new MockHttpSession();
        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456")
                        .session(validSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"));
        assertThat(validSession.getAttribute("user")).isNotNull();
    }

    @Test
    @DisplayName("SQLI-05 [Search]: Chặn UNION/OR SQLi và giữ tìm kiếm thường chính xác")
    void searchBlocksUnionInjectionAndPreservesNormalSearch() throws Exception {
        String unionPayload = "%' UNION SELECT 999, 'SQLI_SEARCH_MARKER', 'Du lieu gia', '12345' -- ";
        mockMvc.perform(get("/search").param("keyword", unionPayload))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(content().string(not(containsString("<h4>SQLI_SEARCH_MARKER</h4>"))))
                .andExpect(content().string(containsString("Không tìm thấy sản phẩm nào")));

        String tautologyPayload = "' OR '1'='1";
        mockMvc.perform(get("/search").param("keyword", tautologyPayload))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Không tìm thấy sản phẩm nào")));

        mockMvc.perform(get("/search").param("keyword", "MacBook"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("MacBook Air M2")));
    }

    @Test
    @DisplayName("SQLI-06 [Product Detail]: Từ chối ID SQLi/sai định dạng/âm mà không chuyển ngầm sang SP khác")
    void productDetailRejectsSqlInjectionAndMalformedIdsWithoutFallback() throws Exception {
        String[] invalidIds = {
                "-1 UNION SELECT 999, 'SQLI_DETAIL_MARKER', 'Mo ta gia', 88888, 'Lab' -- ",
                "1 OR 1=1",
                "0",
                "-5",
                "abc"
        };

        for (String badId : invalidIds) {
            mockMvc.perform(get("/product").param("id", badId))
                    .andExpect(status().isOk())
                    .andExpect(view().name("product"))
                    .andExpect(content().string(containsString("Sản phẩm không tồn tại hoặc đã bị xóa!")))
                    .andExpect(content().string(not(containsString("<h2>SQLI_DETAIL_MARKER</h2>"))))
                    .andExpect(content().string(not(containsString("<h2>iPhone 15 Pro Max</h2>"))));
        }
    }

    @Test
    @DisplayName("SQLI-06 [Add Comment]: Lưu đúng bình luận có dấu nháy đơn và chặn tiêm SQL qua product_id")
    void addCommentPreservesQuotesAndBlocksProductIdInjection() throws Exception {
        String quoteAuthor = "O'Brien";
        String quoteContent = "Máy chạy 'rất mượt', màn hình đẹp & giá hợp lý!";

        mockMvc.perform(post("/product")
                        .param("product_id", "1")
                        .param("author", quoteAuthor)
                        .param("content", quoteContent))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=1"))
                .andExpect(flash().attribute("commentSuccess", "Gửi bình luận đánh giá thành công!"));

        assertThat(countCommentsForProduct(1)).isEqualTo(3);

        mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("O&#39;Brien")))
                .andExpect(content().string(containsString("Máy chạy &#39;rất mượt&#39;, màn hình đẹp &amp; giá hợp lý!")));

        // Thử tấn công SQLi vào product_id (kể cả chứa khoảng trắng, nháy đơn và CRLF)
        String injectedProductId = "1, 'SQLI_INJECTED_AUTHOR', 'SQLI_INSERT_MARKER'), (1";
        mockMvc.perform(post("/product")
                        .param("product_id", injectedProductId)
                        .param("author", "NormalAuthor")
                        .param("content", "NormalContent"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentError", "Mã sản phẩm không hợp lệ!"))
                .andExpect(flash().attribute("commentSuccess", (Object) null));

        // Kiểm tra không có bản ghi tiêm nào được chèn thêm
        assertThat(countCommentsForProduct(1)).isEqualTo(3);

        // Kiểm tra CRLF trong product_id không gây lỗi redirect header
        mockMvc.perform(post("/product")
                        .param("product_id", "1\r\nX-Injected: bad")
                        .param("author", "NormalAuthor")
                        .param("content", "NormalContent"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=invalid"))
                .andExpect(flash().attribute("commentError", "Mã sản phẩm không hợp lệ!"));
    }
}
