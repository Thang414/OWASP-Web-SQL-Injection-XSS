package com.uth.websec;

import com.uth.websec.config.DbConfig;
import com.uth.websec.model.Comment;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "db.url=jdbc:h2:mem:sec_core06_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "db.user=sa",
        "db.pass="
})
class Core06ProductDetailAndCommentTest {

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
    @DisplayName("CORE-06.1: Xem đúng thông tin, giá và danh sách bình luận của sản phẩm mẫu")
    @SuppressWarnings("unchecked")
    void testViewValidProductDisplaysInfoPriceAndComments() throws Exception {
        // Kiểm tra sản phẩm ID=1 có sẵn 2 bình luận mẫu
        MvcResult result = mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")))
                .andExpect(content().string(containsString("29.990.000 VNĐ")))
                .andExpect(content().string(containsString("Điện thoại")))
                .andExpect(content().string(containsString("Nguyễn Văn A")))
                .andExpect(content().string(containsString("Trần Thị B")))
                .andReturn();

        Product product = (Product) result.getModelAndView().getModel().get("product");
        List<Comment> comments = (List<Comment>) result.getModelAndView().getModel().get("comments");
        assertThat(product).isNotNull();
        assertThat(product.getId()).isEqualTo("1");
        assertThat(product.getName()).isEqualTo("iPhone 15 Pro Max");
        assertThat(comments).isNotNull().hasSize(2);

        // Kiểm tra sản phẩm ID=3 chưa có bình luận nào
        MvcResult emptyCommentProduct = mockMvc.perform(get("/products/3"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("Laptop Dell XPS 15")))
                .andExpect(content().string(containsString("35.000.000 VNĐ")))
                .andExpect(content().string(containsString("Chưa có bình luận nào cho sản phẩm này.")))
                .andReturn();

        List<Comment> prod3Comments = (List<Comment>) emptyCommentProduct.getModelAndView().getModel().get("comments");
        assertThat(prod3Comments).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("CORE-06.2: Sản phẩm không tồn tại hoặc ID không hợp lệ hiển thị thông báo phù hợp, không lỗi 500")
    void testViewNonExistentOrInvalidProductShowsFriendlyMessage() throws Exception {
        // Trường hợp ID không tồn tại (id=999)
        MvcResult notFoundResult = mockMvc.perform(get("/product").param("id", "999"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("Sản phẩm không tồn tại hoặc đã bị xóa!")))
                .andExpect(content().string(containsString("Quay lại Trang chủ")))
                .andReturn();

        assertThat(notFoundResult.getModelAndView().getModel().get("product")).isNull();

        // Trường hợp ID sai định dạng số (id=invalid_id)
        MvcResult invalidIdResult = mockMvc.perform(get("/product").param("id", "invalid_id"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("Sản phẩm không tồn tại hoặc đã bị xóa!")))
                .andReturn();

        assertThat(invalidIdResult.getModelAndView().getModel().get("product")).isNull();
    }

    @Test
    @DisplayName("CORE-06.3: Gửi bình luận hợp lệ, lưu vào CSDL và tải lại vẫn thấy đúng sản phẩm, tác giả, nội dung")
    @SuppressWarnings("unchecked")
    void testSubmitValidCommentPersistsAndDisplaysAfterReload() throws Exception {
        String authorName = "Hồng Sơn";
        String commentText = "Sản phẩm chính hãng, giao hàng nhanh và đóng gói rất kỹ!";

        // Bước 1: Gửi bình luận hợp lệ qua POST /product
        mockMvc.perform(post("/product")
                        .param("product_id", "1")
                        .param("author", authorName)
                        .param("content", commentText))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=1"))
                .andExpect(flash().attribute("commentSuccess", "Gửi bình luận đánh giá thành công!"))
                .andExpect(flash().attribute("commentError", (Object) null));

        // Bước 2: Tải lại trang GET /product?id=1 và kiểm chứng bình luận đã lưu trong CSDL
        MvcResult reloadResult = mockMvc.perform(get("/product").param("id", "1")
                        .flashAttr("commentSuccess", "Gửi bình luận đánh giá thành công!"))
                .andExpect(status().isOk())
                .andExpect(view().name("product"))
                .andExpect(content().string(containsString("Gửi bình luận đánh giá thành công!")))
                .andExpect(content().string(containsString("iPhone 15 Pro Max")))
                .andExpect(content().string(containsString(authorName)))
                .andExpect(content().string(containsString(commentText)))
                .andReturn();

        List<Comment> comments = (List<Comment>) reloadResult.getModelAndView().getModel().get("comments");
        assertThat(comments).isNotNull().hasSize(3);
        assertThat(comments.get(0).getProductId()).isEqualTo(1);
        assertThat(comments.get(0).getAuthor()).isEqualTo(authorName);
        assertThat(comments.get(0).getContent()).isEqualTo(commentText);
        assertThat(comments.get(0).getCreatedAt()).isNotNull();
    }

    @Test
    @DisplayName("CORE-06.4: Bình luận có nội dung rỗng hoặc chỉ chứa khoảng trắng bị từ chối kèm thông báo lỗi")
    @SuppressWarnings("unchecked")
    void testSubmitEmptyOrWhitespaceCommentIsRejectedWithMessage() throws Exception {
        // Trường hợp 1: Nội dung rỗng ""
        mockMvc.perform(post("/product")
                        .param("product_id", "1")
                        .param("author", "Hồng Sơn")
                        .param("content", ""))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=1"))
                .andExpect(flash().attribute("commentError", "Nội dung bình luận không được để trống hoặc chỉ chứa khoảng trắng!"))
                .andExpect(flash().attribute("commentSuccess", (Object) null));

        // Trường hợp 2: Nội dung chỉ toàn khoảng trắng "   "
        mockMvc.perform(post("/product")
                        .param("product_id", "1")
                        .param("author", "Hồng Sơn")
                        .param("content", "   \t\n  "))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=1"))
                .andExpect(flash().attribute("commentError", "Nội dung bình luận không được để trống hoặc chỉ chứa khoảng trắng!"))
                .andExpect(flash().attribute("commentSuccess", (Object) null));

        // Kiểm chứng số lượng bình luận của sản phẩm ID=1 vẫn giữ nguyên là 2
        MvcResult checkResult = mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andReturn();
        List<Comment> comments = (List<Comment>) checkResult.getModelAndView().getModel().get("comments");
        assertThat(comments).isNotNull().hasSize(2);
    }

    @Test
    @DisplayName("CORE-06.5: Đầu vào vượt quá độ dài cho phép (author > 50, content > 1000) được xử lý có thông báo")
    @SuppressWarnings("unchecked")
    void testSubmitOverlongAuthorOrContentIsRejectedWithMessage() throws Exception {
        String longAuthor = "A".repeat(55);
        String longContent = "B".repeat(1005);

        // Trường hợp 1: Tên tác giả vượt quá 50 ký tự
        mockMvc.perform(post("/product")
                        .param("product_id", "1")
                        .param("author", longAuthor)
                        .param("content", "Bình luận hợp lệ"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=1"))
                .andExpect(flash().attribute("commentError", "Tên người bình luận không được vượt quá 50 ký tự!"))
                .andExpect(flash().attribute("commentSuccess", (Object) null));

        // Trường hợp 2: Nội dung vượt quá 1000 ký tự
        mockMvc.perform(post("/product")
                        .param("product_id", "1")
                        .param("author", "Hồng Sơn")
                        .param("content", longContent))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=1"))
                .andExpect(flash().attribute("commentError", "Nội dung bình luận không được vượt quá 1000 ký tự!"))
                .andExpect(flash().attribute("commentSuccess", (Object) null));

        // Kiểm chứng không có bình luận rác nào được lưu vào CSDL
        MvcResult checkResult = mockMvc.perform(get("/product").param("id", "1"))
                .andExpect(status().isOk())
                .andReturn();
        List<Comment> comments = (List<Comment>) checkResult.getModelAndView().getModel().get("comments");
        assertThat(comments).isNotNull().hasSize(2);
    }

    @Test
    @DisplayName("CORE-06.6: Không báo thành công giả khi lưu bình luận thất bại (sản phẩm không tồn tại)")
    void testNoFalsePositiveSuccessWhenDatabaseInsertFails() throws Exception {
        // Gửi bình luận vào product_id=999 (vi phạm khóa ngoại FOREIGN KEY trên bảng comments)
        mockMvc.perform(post("/product")
                        .param("product_id", "999")
                        .param("author", "Hồng Sơn")
                        .param("content", "Thử gửi bình luận cho sản phẩm không tồn tại"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/product?id=999"))
                .andExpect(flash().attribute("commentError", "Không thể lưu bình luận: Sản phẩm không tồn tại hoặc dữ liệu không hợp lệ!"))
                .andExpect(flash().attribute("commentSuccess", (Object) null));
    }
}
