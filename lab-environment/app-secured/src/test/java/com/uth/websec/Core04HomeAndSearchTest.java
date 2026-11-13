package com.uth.websec;

import com.uth.websec.config.DbConfig;
import com.uth.websec.model.Product;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:secured_core04_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class Core04HomeAndSearchTest {

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
    @DisplayName("CORE-04.1: Trang chủ bảo mật hiển thị đầy đủ 5 sản phẩm từ CSDL kèm giá định dạng chuẩn")
    @SuppressWarnings("unchecked")
    void testHomePageDisplaysAllSeedProducts() throws Exception {
        MvcResult result = mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")))
                .andExpect(content().string(containsString("Samsung Galaxy S24 Ultra")))
                .andExpect(content().string(containsString("Laptop Dell XPS 15")))
                .andExpect(content().string(containsString("MacBook Air M2")))
                .andExpect(content().string(containsString("Tai nghe Sony WH-1000XM5")))
                .andExpect(content().string(containsString("29.990.000 VNĐ")))
                .andReturn();

        List<Product> products = (List<Product>) result.getModelAndView().getModel().get("products");
        assertThat(products).isNotNull().hasSize(5);
    }

    @Test
    @DisplayName("CORE-04.2: Mỗi sản phẩm trên danh sách có link điều hướng chính xác sang trang chi tiết")
    void testProductLinksNavigateToProductDetail() throws Exception {
        mockMvc.perform(get("/index.php"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/product?id=1")))
                .andExpect(content().string(containsString("/product?id=2")))
                .andExpect(content().string(containsString("/product?id=3")))
                .andExpect(content().string(containsString("/product?id=4")))
                .andExpect(content().string(containsString("/product?id=5")));

        mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")));

        mockMvc.perform(get("/products/2"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("Samsung Galaxy S24 Ultra")));
    }

    @Test
    @DisplayName("CORE-04.3: Tìm kiếm an toàn với từ khóa có kết quả trả về đúng danh sách sản phẩm khớp")
    @SuppressWarnings("unchecked")
    void testSearchWithMatchingKeywordReturnsProducts() throws Exception {
        MvcResult singleMatch = mockMvc.perform(get("/search").param("keyword", "iPhone"))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(model().attribute("isBlankSearch", false))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")))
                .andExpect(content().string(containsString("/product?id=1")))
                .andReturn();

        List<Product> singleList = (List<Product>) singleMatch.getModelAndView().getModel().get("products");
        assertThat(singleList).isNotNull().hasSize(1);
        assertThat(singleList.get(0).getName()).isEqualTo("iPhone 15 Pro Max");

        MvcResult multiMatch = mockMvc.perform(get("/search").param("keyword", "M"))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andReturn();

        List<Product> multiList = (List<Product>) multiMatch.getModelAndView().getModel().get("products");
        assertThat(multiList).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("CORE-04.4: Tìm kiếm an toàn với từ khóa không có kết quả hiển thị thông báo rõ ràng, không lỗi 500")
    @SuppressWarnings("unchecked")
    void testSearchWithNonMatchingKeywordShowsEmptyMessage() throws Exception {
        String nonExistentKeyword = "Nokia1280KhongTonTai";
        MvcResult result = mockMvc.perform(get("/search").param("keyword", nonExistentKeyword))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(model().attribute("isBlankSearch", false))
                .andExpect(content().string(containsString("Không tìm thấy sản phẩm nào phù hợp với từ khóa")))
                .andExpect(content().string(containsString(nonExistentKeyword)))
                .andReturn();

        List<Product> products = (List<Product>) result.getModelAndView().getModel().get("products");
        assertThat(products).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("CORE-04.5: Tìm kiếm an toàn với từ khóa rỗng hoặc chỉ chứa khoảng trắng trả về toàn bộ 5 sản phẩm mặc định")
    @SuppressWarnings("unchecked")
    void testSearchWithEmptyOrWhitespaceKeywordReturnsDefaultProducts() throws Exception {
        // Trường hợp 1: Từ khóa rỗng ""
        MvcResult emptyResult = mockMvc.perform(get("/search").param("keyword", ""))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(model().attribute("isBlankSearch", true))
                .andExpect(content().string(containsString("Từ khóa tìm kiếm đang trống hoặc chỉ chứa khoảng trắng")))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")))
                .andExpect(content().string(containsString("Tai nghe Sony WH-1000XM5")))
                .andReturn();

        List<Product> emptyProducts = (List<Product>) emptyResult.getModelAndView().getModel().get("products");
        assertThat(emptyProducts).isNotNull().hasSize(5);

        // Trường hợp 2: Từ khóa chỉ chứa khoảng trắng "   "
        MvcResult whitespaceResult = mockMvc.perform(get("/search").param("keyword", "   "))
                .andExpect(status().isOk())
                .andExpect(view().name("search"))
                .andExpect(model().attribute("isBlankSearch", true))
                .andExpect(content().string(containsString("Từ khóa tìm kiếm đang trống hoặc chỉ chứa khoảng trắng")))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")))
                .andExpect(content().string(containsString("Tai nghe Sony WH-1000XM5")))
                .andReturn();

        List<Product> whitespaceProducts = (List<Product>) whitespaceResult.getModelAndView().getModel().get("products");
        assertThat(whitespaceProducts).isNotNull().hasSize(5);
    }
}
