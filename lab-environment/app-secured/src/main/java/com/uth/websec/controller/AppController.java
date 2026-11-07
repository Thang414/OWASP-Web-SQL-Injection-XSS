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
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
public class AppController {

    private static final String SECURED_TOKEN_SUFFIX = "_secured_token_8081";

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
                    if (decoded.endsWith(SECURED_TOKEN_SUFFIX)) {
                        String username = decoded.substring(0, decoded.length() - SECURED_TOKEN_SUFFIX.length());
                        if (!username.isBlank()) {
                            User resolved = findUserByUsername(username);
                            if (resolved != null) {
                                session.setAttribute("user", resolved);
                                return resolved;
                            }
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

    private void attachSecuredSessionCookie(User user, HttpServletResponse response) {
        String token = Base64.getEncoder().encodeToString(
                (user.getUsername() + SECURED_TOKEN_SUFFIX).getBytes(StandardCharsets.UTF_8)
        );
        ResponseCookie cookie = ResponseCookie.from("session_token", token)
                .httpOnly(true) // BẢO MẬT: Ngăn chặn JavaScript đọc trộm cookie qua XSS
                .sameSite("Strict") // BẢO MẬT: Chống tấn công CSRF
                .secure(false) // Đặt true khi chạy môi trường HTTPS
                .path("/")
                .maxAge(3600)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearSecuredSessionCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("session_token", "")
                .httpOnly(true)
                .sameSite("Strict")
                .secure(false)
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    // 1. Trang chủ danh sách sản phẩm (Secured)
    @GetMapping({"/", "/index.php"})
    public String index(HttpSession session, HttpServletRequest request, HttpServletResponse response, Model model) {
        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);

        // Đính kèm cookie phiên an toàn: BẬT CỜ HTTPONLY
        if (user != null) {
            attachSecuredSessionCookie(user, response);
        }

        List<Product> products = new ArrayList<>();
        try (Connection conn = dbConfig.getConnection();
             PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products");
             ResultSet rs = pstmt.executeQuery()) {

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

    // 2. Tìm kiếm sản phẩm (PHÒNG THỦ: PREPARED STATEMENT + THYMELEAF AUTO-ESCAPING)
    @GetMapping({"/search", "/search.php"})
    public String search(@RequestParam(name = "keyword", defaultValue = "") String keyword,
                         HttpSession session,
                         HttpServletRequest request,
                         Model model) {
        String cleanKeyword = keyword.trim();
        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);
        model.addAttribute("keyword", cleanKeyword);

        List<Product> products = new ArrayList<>();

        if (!cleanKeyword.isEmpty()) {
            // PHÒNG THỦ SQL INJECTION: PreparedStatement phân tách mã SQL và dữ liệu
            String sql = "SELECT id, name, description, price FROM products WHERE name LIKE ?";
            try (Connection conn = dbConfig.getConnection();
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, "%" + cleanKeyword + "%");

                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        products.add(new Product(
                                rs.getString("id"),
                                rs.getString("name"),
                                rs.getString("description"),
                                rs.getString("price"),
                                ""
                        ));
                    }
                }
            } catch (Exception e) {
                System.err.println("Lỗi tìm kiếm: " + e.getMessage());
            }
        }

        model.addAttribute("products", products);
        return "search";
    }

    // 3. Chi tiết sản phẩm & Bình luận (Secured)
    @GetMapping({"/product", "/product.php"})
    public String productDetail(@RequestParam(name = "id", defaultValue = "1") String idStr,
                                HttpSession session,
                                HttpServletRequest request,
                                Model model) {
        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);

        int id = 1;
        try {
            id = Integer.parseInt(idStr);
        } catch (NumberFormatException ignored) {}

        model.addAttribute("productId", id);
        Product product = null;
        List<Comment> comments = new ArrayList<>();

        try (Connection conn = dbConfig.getConnection()) {
            // Lấy thông tin sản phẩm (Prepared Statement)
            try (PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE id = ?")) {
                pstmt.setInt(1, id);
                try (ResultSet rs = pstmt.executeQuery()) {
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
            }

            // Lấy danh sách bình luận (Prepared Statement)
            try (PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM comments WHERE product_id = ? ORDER BY id DESC")) {
                pstmt.setInt(1, id);
                try (ResultSet rs = pstmt.executeQuery()) {
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
            }
        } catch (Exception e) {
            model.addAttribute("error", "Lỗi CSDL: " + e.getMessage());
        }

        model.addAttribute("product", product);
        model.addAttribute("comments", comments);
        return "product";
    }

    // Gửi bình luận (PHÒNG THỦ: PREPARED STATEMENT + VALIDATION)
    @PostMapping({"/product", "/product.php"})
    public String addComment(@RequestParam("product_id") String productIdStr,
                             @RequestParam(name = "author", defaultValue = "Khách hàng") String author,
                             @RequestParam("content") String content) {
        int productId = 1;
        try {
            productId = Integer.parseInt(productIdStr);
        } catch (NumberFormatException ignored) {}

        String cleanAuthor = author.trim();
        if (cleanAuthor.length() > 50) {
            cleanAuthor = cleanAuthor.substring(0, 50);
        }
        String cleanContent = content.trim();

        if (!cleanContent.isEmpty()) {
            // PHÒNG THỦ SQL INJECTION: PreparedStatement
            String sql = "INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)";
            try (Connection conn = dbConfig.getConnection();
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setInt(1, productId);
                pstmt.setString(2, cleanAuthor);
                pstmt.setString(3, cleanContent);
                pstmt.executeUpdate();
            } catch (Exception e) {
                System.err.println("Lỗi lưu bình luận: " + e.getMessage());
            }
        }

        return "redirect:/product?id=" + productId;
    }

    // 4. Đăng nhập (PHÒNG THỦ: PREPARED STATEMENT)
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

        String cleanUser = username.trim();
        String cleanPass = password.trim();

        // PHÒNG THỦ SQL INJECTION: PreparedStatement với tham số hóa ?
        String sql = "SELECT * FROM users WHERE username = ? AND password = ?";

        try (Connection conn = dbConfig.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, cleanUser);
            pstmt.setString(2, cleanPass);

            try (ResultSet rs = pstmt.executeQuery()) {
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

                    // Thiết lập Cookie AN TOÀN: BẬT CỜ HTTPONLY
                    attachSecuredSessionCookie(user, response);

                    return "redirect:/index.php";
                } else {
                    session.removeAttribute("user");
                    clearSecuredSessionCookie(response);
                    model.addAttribute("user", null);
                    model.addAttribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!");
                    return "login";
                }
            }
        } catch (Exception e) {
            session.removeAttribute("user");
            clearSecuredSessionCookie(response);
            model.addAttribute("user", null);
            model.addAttribute("message", "Lỗi hệ thống: " + e.getMessage());
            return "login";
        }
    }

    // 5. Đăng xuất
    @GetMapping({"/logout", "/logout.php"})
    public String logout(HttpSession session, HttpServletResponse response, RedirectAttributes redirectAttributes) {
        session.invalidate();
        clearSecuredSessionCookie(response);
        redirectAttributes.addFlashAttribute("logoutMessage", "Bạn đã đăng xuất khỏi phiên làm việc thành công.");
        return "redirect:/login.php";
    }
}
