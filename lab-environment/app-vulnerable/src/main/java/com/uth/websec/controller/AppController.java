package com.uth.websec.controller;

import com.uth.websec.config.DbConfig;
import com.uth.websec.model.Comment;
import com.uth.websec.model.Product;
import com.uth.websec.model.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
public class AppController {

    @Autowired
    private DbConfig dbConfig;

    // 1. Trang chủ danh sách sản phẩm (hỗ trợ cả / và /index.php)
    @GetMapping({"/", "/index.php"})
    public String index(HttpSession session, HttpServletResponse response, Model model) {
        User user = (User) session.getAttribute("user");
        model.addAttribute("user", user);

        // Đính kèm cookie phiên thông thường (KHÔNG cờ HttpOnly -> XSS đọc được)
        if (user != null) {
            String token = Base64.getEncoder().encodeToString((user.getUsername() + "_secret_token_123").getBytes(StandardCharsets.UTF_8));
            Cookie cookie = new Cookie("session_token", token);
            cookie.setHttpOnly(false); // LỖ HỔNG BẢO MẬT: Cho phép JavaScript truy cập
            cookie.setPath("/");
            cookie.setMaxAge(3600);
            response.addCookie(cookie);
        }

        List<Product> products = new ArrayList<>();
        try (Connection conn = dbConfig.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM products")) {

            while (rs.next()) {
                products.add(new Product(
                        rs.getString("id"),
                        rs.getString("name"),
                        rs.getString("description"),
                        rs.getString("price"),
                        rs.getString("category")
                ));
            }
        } catch (Exception e) {
            model.addAttribute("error", "Lỗi CSDL: " + e.getMessage());
        }

        model.addAttribute("products", products);
        return "index";
    }

    // 2. Tìm kiếm sản phẩm (LỖ HỔNG SQL INJECTION + REFLECTED XSS)
    @GetMapping({"/search", "/search.php"})
    public String search(@RequestParam(name = "keyword", defaultValue = "") String keyword,
                         HttpSession session,
                         Model model) {
        model.addAttribute("user", session.getAttribute("user"));
        model.addAttribute("keyword", keyword);

        // LỖ HỔNG 1: SQL INJECTION (Nối chuỗi trực tiếp)
        String sql = "SELECT id, name, description, price FROM products WHERE name LIKE '%" + keyword + "%'";
        model.addAttribute("sql", sql);

        List<Product> products = new ArrayList<>();
        String sqlError = null;

        if (!keyword.isEmpty()) {
            try (Connection conn = dbConfig.getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {

                while (rs.next()) {
                    products.add(new Product(
                            rs.getString(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4),
                            ""
                    ));
                }
            } catch (Exception e) {
                sqlError = e.getMessage();
            }
        }

        model.addAttribute("products", products);
        model.addAttribute("sqlError", sqlError);
        return "search";
    }

    // 3. Chi tiết sản phẩm & Đánh giá (LỖ HỔNG STORED XSS)
    @GetMapping({"/product", "/product.php"})
    public String productDetail(@RequestParam(name = "id", defaultValue = "1") String id,
                                HttpSession session,
                                Model model) {
        User user = (User) session.getAttribute("user");
        model.addAttribute("user", user);
        model.addAttribute("productId", id);

        Product product = null;
        List<Comment> comments = new ArrayList<>();

        try (Connection conn = dbConfig.getConnection();
             Statement stmt = conn.createStatement()) {

            // Lấy thông tin sản phẩm (Nối chuỗi id)
            try (ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE id = " + id)) {
                if (rs.next()) {
                    product = new Product(
                            rs.getString("id"),
                            rs.getString("name"),
                            rs.getString("description"),
                            rs.getString("price"),
                            rs.getString("category")
                    );
                }
            }

            // Lấy danh sách bình luận (Nối chuỗi id)
            try (ResultSet rs = stmt.executeQuery("SELECT * FROM comments WHERE product_id = " + id + " ORDER BY id DESC")) {
                while (rs.next()) {
                    comments.add(new Comment(
                            rs.getInt("id"),
                            rs.getInt("product_id"),
                            rs.getString("author"),
                            rs.getString("content"),
                            rs.getString("created_at")
                    ));
                }
            }
        } catch (Exception e) {
            model.addAttribute("error", "Lỗi CSDL: " + e.getMessage());
        }

        model.addAttribute("product", product);
        model.addAttribute("comments", comments);
        return "product";
    }

    // Gửi bình luận sản phẩm (LỖ HỔNG STORED XSS & SQLi)
    @PostMapping({"/product", "/product.php"})
    public String addComment(@RequestParam("product_id") String productId,
                             @RequestParam(name = "author", defaultValue = "Khách hàng") String author,
                             @RequestParam("content") String content) {
        try (Connection conn = dbConfig.getConnection();
             Statement stmt = conn.createStatement()) {

            // LƯU TRỰC TIẾP VÀO DATABASE MÀ KHÔNG SANITIZE / ENCODE
            String insertSql = "INSERT INTO comments (product_id, author, content) VALUES (" +
                    productId + ", '" + author + "', '" + content + "')";
            stmt.executeUpdate(insertSql);
        } catch (Exception e) {
            System.err.println("Lỗi thêm bình luận: " + e.getMessage());
        }

        return "redirect:/product?id=" + productId;
    }

    // 4. Đăng nhập (LỖ HỔNG SQL INJECTION AUTHENTICATION BYPASS)
    @GetMapping({"/login", "/login.php"})
    public String loginPage(Model model) {
        model.addAttribute("message", null);
        return "login";
    }

    @PostMapping({"/login", "/login.php"})
    public String doLogin(@RequestParam(name = "username", defaultValue = "") String username,
                          @RequestParam(name = "password", defaultValue = "") String password,
                          HttpSession session,
                          HttpServletResponse response,
                          Model model) {

        // LỖ HỔNG SQL INJECTION: Nối chuỗi xác thực tài khoản
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        System.out.println("[DEBUG SQL VULNERABLE LOGIN]: " + sql);

        try (Connection conn = dbConfig.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                User user = new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        "",
                        rs.getString("full_name"),
                        rs.getString("role"),
                        rs.getString("credit_card")
                );

                session.setAttribute("user", user);

                // Thiết lập Cookie KHÔNG có cờ HttpOnly -> Dễ bị cướp qua XSS
                String token = Base64.getEncoder().encodeToString((user.getUsername() + "_token_secret_auth").getBytes(StandardCharsets.UTF_8));
                Cookie cookie = new Cookie("session_token", token);
                cookie.setHttpOnly(false); // LỖ HỔNG
                cookie.setPath("/");
                cookie.setMaxAge(3600);
                response.addCookie(cookie);

                return "redirect:/index.php";
            } else {
                model.addAttribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!");
                return "login";
            }
        } catch (Exception e) {
            model.addAttribute("message", "Lỗi truy vấn SQL: " + e.getMessage());
            return "login";
        }
    }

    // 5. Đăng xuất
    @GetMapping({"/logout", "/logout.php"})
    public String logout(HttpSession session, HttpServletResponse response) {
        session.invalidate();
        Cookie cookie = new Cookie("session_token", "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return "redirect:/login.php";
    }
}
