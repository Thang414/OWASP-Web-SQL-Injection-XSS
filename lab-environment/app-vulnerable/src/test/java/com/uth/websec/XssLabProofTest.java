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
import java.sql.Statement;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * XSS-02 / XSS-03 / XSS-04 / VERIFY-02 (ANM-39, ANM-40, ANM-41, ANM-47):
 * Chứng minh Reflected XSS và Stored XSS bằng mã minh họa vô hại (không đọc/gửi cookie)
 * trên app-vulnerable, kèm ca đối chứng hợp lệ.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:vuln_xss_proof_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class XssLabProofTest {

    static final String HARMLESS_REFLECTED_DOM =
            "<span id=\"rxss-marker\"></span><script>document.getElementById(\"rxss-marker\").textContent=\"RXSS_EXECUTED\"</script>";
    static final String HARMLESS_STORED_DOM =
            "<span id=\"sxss-marker\"></span><script>document.getElementById(\"sxss-marker\").textContent=\"SXSS_EXECUTED\"</script>";

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
    @DisplayName("XSS-03 [Reflected]: Phản chiếu nguyên văn mã vô hại tại /search (th:utext) và vẫn tìm kiếm bình thường")
    void reflectedXssHarmlessPayloadAndNormalSearchContrast() throws Exception {
        mockMvc.perform(get("/search").param("keyword", HARMLESS_REFLECTED_DOM))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(content().string(containsString(HARMLESS_REFLECTED_DOM)));

        // Ca đối chứng từ khóa hợp lệ
        mockMvc.perform(get("/search").param("keyword", "Sony"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Tai nghe Sony WH-1000XM5")));
    }

    @Test
    @DisplayName("XSS-04 [Stored]: Lưu bình luận chứa mã vô hại và xuất hiện nguyên văn cho mọi lượt xem sau tải lại")
    void storedXssHarmlessPayloadPersistsAcrossIndependentViews() throws Exception {
        mockMvc.perform(post("/product")
                        .param("product_id", "2")
                        .param("author", "SinhVienLab")
                        .param("content", HARMLESS_STORED_DOM))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=2"))
                .andExpect(flash().attribute("commentSuccess", "Gửi bình luận đánh giá thành công!"));

        // Tải lại độc lập mô phỏng hai phiên xem khác nhau
        mockMvc.perform(get("/product").param("id", "2"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(HARMLESS_STORED_DOM)));

        mockMvc.perform(get("/product").param("id", "2"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(HARMLESS_STORED_DOM)));
    }
}
