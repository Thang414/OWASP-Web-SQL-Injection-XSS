package com.uth.websec.controller;

import com.uth.websec.config.DbConfig;
import com.uth.websec.model.Comment;
import com.uth.websec.model.Product;
import com.uth.websec.model.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
public class AppController {

    private static final String TOKEN_SUFFIX = "_token_secret_auth";
    private static final String LEGACY_TOKEN_SUFFIX = "_secret_token_123";

    @Autowired
    private DbConfig dbConfig;

    private User resolveSessionUser(HttpSession session, HttpServletRequest request) {
        User sessionUser = (User) session.getAttribute("user");
        if (sessionUser != null) {
            return sessionUser;
        }
        if (request == null || request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if ("session_token".equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                try {
                    String decoded = new String(
                            Base64.getDecoder().decode(cookie.getValue().trim()),
                            StandardCharsets.UTF_8
                    );
                    String username = null;
                    if (decoded.endsWith(TOKEN_SUFFIX)) {
                        username = decoded.substring(0, decoded.length() - TOKEN_SUFFIX.length());
                    } else if (decoded.endsWith(LEGACY_TOKEN_SUFFIX)) {
                        username = decoded.substring(0, decoded.length() - LEGACY_TOKEN_SUFFIX.length());
                    }
                    if (username != null && !username.isBlank()) {
                        User resolved = findUserByUsername(username);
                        if (resolved != null) {
                            session.setAttribute("user", resolved);
                            return resolved;
                        }
                    }
                } catch (IllegalArgumentException ignored) {
                    // Bỏ qua nếu cookie không đúng định dạng Base64
                }
            }
        }
        return null;
    }

    private User findUserByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        try (Connection conn = dbConfig.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new User(
                            rs.getInt("id"),
                            rs.getString("username"),
                            "",
                            rs.getString("full_name"),
                            rs.getString("role"),
                            rs.getString("credit_card")
                    );
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private void attachVulnerableSessionCookie(User user, HttpServletResponse response) {
        String token = Base64.getEncoder().encodeToString(
                (user.getUsername() + TOKEN_SUFFIX).getBytes(StandardCharsets.UTF_8)
        );
        Cookie cookie = new Cookie("session_token", token);
        cookie.setHttpOnly(false); // LỖ HỔNG BẢO MẬT: Cho phép JavaScript truy cập qua document.cookie
        cookie.setPath("/");
        cookie.setMaxAge(3600);
        response.addCookie(cookie);
    }

    private void clearVulnerableSessionCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("session_token", "");
        cookie.setHttpOnly(false);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    // 1. Trang chủ danh sách sản phẩm (hỗ trợ cả / và /index.php)
    @GetMapping({"/", "/index.php"})
    public String index(HttpSession session, HttpServletRequest request, HttpServletResponse response, Model model) {
        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);

        // Đính kèm cookie phiên thông thường (KHÔNG cờ HttpOnly -> XSS đọc được)
        if (user != null) {
            attachVulnerableSessionCookie(user, response);
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
                         HttpServletRequest request,
                         Model model) {
        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);
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
                                HttpServletRequest request,
                                Model model) {
        User user = resolveSessionUser(session, request);
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
    public String loginPage(@RequestParam(name = "logout", required = false) String logout,
                            HttpSession session,
                            HttpServletRequest request,
                            Model model) {
        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);
        if (!model.containsAttribute("message")) {
            model.addAttribute("message", null);
        }
        if ("1".equals(logout) || "true".equalsIgnoreCase(logout)) {
            model.addAttribute("logoutMessage", "Bạn đã đăng xuất khỏi phiên làm việc thành công.");
        }
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
                attachVulnerableSessionCookie(user, response);

                return "redirect:/index.php";
            } else {
                session.removeAttribute("user");
                clearVulnerableSessionCookie(response);
                model.addAttribute("user", null);
                model.addAttribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!");
                return "login";
            }
        } catch (Exception e) {
            session.removeAttribute("user");
            clearVulnerableSessionCookie(response);
            model.addAttribute("user", null);
            model.addAttribute("message", "Lỗi truy vấn SQL: " + e.getMessage());
            return "login";
        }
    }

    // 5. Đăng xuất
    @GetMapping({"/logout", "/logout.php"})
    public String logout(HttpSession session, HttpServletResponse response, RedirectAttributes redirectAttributes) {
        session.invalidate();
        clearVulnerableSessionCookie(response);
        redirectAttributes.addFlashAttribute("logoutMessage", "Bạn đã đăng xuất khỏi phiên làm việc thành công.");
        return "redirect:/login.php";
    }
}
