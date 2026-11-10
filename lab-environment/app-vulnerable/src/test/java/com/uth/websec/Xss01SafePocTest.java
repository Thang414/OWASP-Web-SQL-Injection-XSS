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
import java.sql.ResultSet;
import java.sql.Statement;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * XSS-01 (ANM-38): Kiểm chứng PoC vô hại cho Reflected XSS và Stored XSS trên app-vulnerable.
 * Payload chỉ dùng console.log / thẻ HTML hiển thị, không đọc cookie và không gửi dữ liệu ra ngoài.
 * MockMvc không thực thi JavaScript: bài test kiểm chứng việc payload được phản chiếu/lưu NGUYÊN VĂN
 * (điều kiện cần để trình duyệt thực thi), header CSP và cờ HttpOnly của cookie phiên.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:vuln_xss01_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class Xss01SafePocTest {

    static final String R1_SCRIPT = "<script>console.log(\"XSS-01 R1 reflected\")</script>";
    static final String R3_EVENT = "<img src=x onerror=\"console.log(document.title)\">";
    static final String S1_SCRIPT = "<script>console.log(\"XSS-01 S1 stored\")</script>";
    static final String S2_MARKUP = "<mark>XSS-01 S2 stored HTML</mark>";

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

    private int countCommentsContaining(String marker) throws Exception {
        try (Connection conn = dbConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM comments WHERE content LIKE ?")) {
            ps.setString(1, "%" + marker + "%");
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private String findStoredContent(String marker) throws Exception {
        try (Connection conn = dbConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT content FROM comments WHERE content LIKE ?")) {
            ps.setString(1, "%" + marker + "%");
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    @Test
    @DisplayName("XSS-01.1: Reflected - payload R1/R3 duoc phan chieu NGUYEN VAN trong phan hoi /search (sink th:utext)")
    void reflectedPayloadIsEchoedRawInSearchResponse() throws Exception {
        mockMvc.perform(get("/search").param("keyword", R1_SCRIPT))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(content().string(containsString(R1_SCRIPT)));

        mockMvc.perform(get("/search").param("keyword", R3_EVENT))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(R3_EVENT)));
    }

    @Test
    @DisplayName("XSS-01.2: Reflected - payload chi ton tai trong 1 cap request/response, KHONG duoc luu vao CSDL va KHONG xuat hien o request sau")
    void reflectedPayloadIsNotPersisted() throws Exception {
        mockMvc.perform(get("/search").param("keyword", R1_SCRIPT))
                .andExpect(status().isOk());

        assertEquals(0, countCommentsContaining("XSS-01 R1"));

        mockMvc.perform(get("/search").param("keyword", "iPhone"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("XSS-01 R1"))));
    }

    @Test
    @DisplayName("XSS-01.3: Stored - payload S1/S2 duoc luu NGUYEN VAN vao bang comments va hien thi lai tho cho moi lan tai trang")
    void storedPayloadIsPersistedAndRenderedRaw() throws Exception {
        for (String payload : new String[]{S1_SCRIPT, S2_MARKUP}) {
            mockMvc.perform(post("/product")
                            .param("product_id", "1")
                            .param("author", "lab_tester")
                            .param("content", payload))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(flash().attribute("commentSuccess", "Gửi bình luận đánh giá thành công!"));
        }

        assertEquals(S1_SCRIPT, findStoredContent("XSS-01 S1"));
        assertEquals(S2_MARKUP, findStoredContent("XSS-01 S2"));

        // Hai lan tai trang doc lap (mo phong 2 nguoi xem khac nhau) deu nhan payload tho
        for (int visit = 0; visit < 2; visit++) {
            mockMvc.perform(get("/product").param("id", "1"))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString(S1_SCRIPT)))
                    .andExpect(content().string(containsString(S2_MARKUP)));
        }
    }

    @Test
    @DisplayName("XSS-01.4: Lop bo sung - app-vulnerable KHONG gui header Content-Security-Policy")
    void noContentSecurityPolicyHeader() throws Exception {
        mockMvc.perform(get("/search").param("keyword", R1_SCRIPT))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Content-Security-Policy"));
    }

    @Test
    @DisplayName("XSS-01.5: Lop bo sung - cookie session_token cua app-vulnerable THIEU co HttpOnly")
    void sessionCookieIsMissingHttpOnly() throws Exception {
        mockMvc.perform(post("/login")
                        .param("username", "nguyenvana")
                        .param("password", "pass123456"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().stringValues("Set-Cookie",
                        hasItem(allOf(startsWith("session_token="), not(containsString("HttpOnly"))))));
    }
}
