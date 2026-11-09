package com.uth.websec;

import com.uth.websec.model.Comment;
import com.uth.websec.model.Product;
import com.uth.websec.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ModelMappingTest {

    @Test
    @DisplayName("Kiểm tra ánh xạ thực thể User và các trường dữ liệu giả")
    void testUserModelMapping() {
        User user = new User(1, "admin", "admin123_super_secret", "Quản Trị Viên Hệ Thống", "admin", "4111-2222-3333-4444");

        assertThat(user.getId()).isEqualTo(1);
        assertThat(user.getUsername()).isEqualTo("admin");
        assertThat(user.getPassword()).isEqualTo("admin123_super_secret");
        assertThat(user.getFullName()).isEqualTo("Quản Trị Viên Hệ Thống");
        assertThat(user.getRole()).isEqualTo("admin");
        assertThat(user.getCreditCard()).isEqualTo("4111-2222-3333-4444");

        User customer = new User();
        customer.setId(2);
        customer.setUsername("nguyenvana");
        customer.setFullName("Nguyễn Văn A");
        customer.setRole("customer");

        assertThat(customer.getId()).isEqualTo(2);
        assertThat(customer.getUsername()).isEqualTo("nguyenvana");
        assertThat(customer.getFullName()).isEqualTo("Nguyễn Văn A");
        assertThat(customer.getRole()).isEqualTo("customer");
    }

    @Test
    @DisplayName("Kiểm tra ánh xạ thực thể Product, định dạng giá và logic ảnh minh họa")
    void testProductModelMappingAndFormatting() {
        Product p1 = new Product("1", "iPhone 15 Pro Max", "Apple 256GB Titan", "29990000.00", "Điện thoại");

        assertThat(p1.getId()).isEqualTo("1");
        assertThat(p1.getName()).isEqualTo("iPhone 15 Pro Max");
        assertThat(p1.getPrice()).isEqualTo("29990000.00");
        assertThat(p1.getFormattedPrice()).isEqualTo("29.990.000 VNĐ");
        assertThat(p1.getImageUrl()).isEqualTo("/images/products/iphone-15-pro-max.jpg");

        // Kiểm tra xử lý giá rỗng / null
        Product pEmpty = new Product("99", "SP Chưa Có Giá", "Mô tả", null, "Khác");
        assertThat(pEmpty.getFormattedPrice()).isEqualTo("0 VNĐ");

        // Kiểm tra xử lý giá bị tiêm SQL Union-based (dữ liệu chuỗi không phải số)
        Product pInjected = new Product("100", "SP Bị Tiêm", "Mô tả", "admin:admin123_super_secret", "Điện thoại");
        assertThat(pInjected.getFormattedPrice()).isEqualTo("admin:admin123_super_secret");

        // Kiểm tra fallback ảnh mặc định cho thiết bị lạ
        Product pUnknown = new Product("101", "Bàn Phím Cơ Custom", "Mô tả", "1500000", "Phụ kiện");
        assertThat(pUnknown.getImageUrl()).isEqualTo("/images/products/default-device.svg");
    }

    @Test
    @DisplayName("Kiểm tra ánh xạ thực thể Comment và quan hệ với Product")
    void testCommentModelMappingAndRelationship() {
        Comment comment = new Comment(1, 1, "Nguyễn Văn A", "Sản phẩm dùng rất mượt!", "2026-11-08 17:40:30");

        assertThat(comment.getId()).isEqualTo(1);
        assertThat(comment.getProductId()).isEqualTo(1);
        assertThat(comment.getAuthor()).isEqualTo("Nguyễn Văn A");
        assertThat(comment.getContent()).isEqualTo("Sản phẩm dùng rất mượt!");
        assertThat(comment.getCreatedAt()).isEqualTo("2026-11-08 17:40:30");

        Comment cNew = new Comment();
        cNew.setId(2);
        cNew.setProductId(1);
        cNew.setAuthor("Trần Thị B");
        cNew.setContent("Pin trâu, dùng cả ngày thoải mái.");
        cNew.setCreatedAt("2026-11-08 18:00:00");

        assertThat(cNew.getProductId()).isEqualTo(1);
        assertThat(cNew.getAuthor()).isEqualTo("Trần Thị B");
    }
}
