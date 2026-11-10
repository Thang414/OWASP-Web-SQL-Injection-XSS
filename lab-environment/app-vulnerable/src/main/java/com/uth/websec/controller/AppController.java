package com.uth.websec.controller;

import com.uth.websec.config.DbConfig;
import com.uth.websec.model.Comment;
import com.uth.websec.model.Product;
import com.uth.websec.model.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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

    private static final Logger log = LoggerFactory.getLogger(AppController.class);
    private static final String TOKEN_SUFFIX = "_token_secret_auth";
    private static final String LEGACY_TOKEN_SUFFIX = "_secret_token_123";

    @Autowired
    private DbConfig dbConfig;

    public User resolveSessionUser(HttpSession session, HttpServletRequest request) {
        if (session == null) {
            return null;
        }
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
            log.info("[CORE-04][HOME] Hien thi trang chu (vulnerable) - Tong so san pham: {}", products.size());
        } catch (Exception e) {
            log.error("[CORE-04][HOME][ERROR] Loi truy van danh sach san pham: {}", e.getMessage());
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

        boolean isBlankKeyword = (keyword == null || keyword.trim().isEmpty());
        String displayKeyword = isBlankKeyword ? "" : keyword;
        model.addAttribute("keyword", displayKeyword);
        model.addAttribute("isBlankSearch", isBlankKeyword);

        List<Product> products = new ArrayList<>();
        String sqlError = null;
        String sql;

        if (isBlankKeyword) {
            // Trường hợp 3: Từ khóa rỗng hoặc chỉ chứa khoảng trắng -> Trả về toàn bộ danh sách sản phẩm mặc định
            sql = "SELECT id, name, description, price FROM products";
            model.addAttribute("sql", sql);
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
                log.info("[CORE-04][SEARCH][BLANK_KEYWORD] Tu khoa rong hoac chi chua khoang trang (raw='{}') -> Tra ve toan bo {} san pham mac dinh",
                        keyword, products.size());
            } catch (Exception e) {
                sqlError = e.getMessage();
                log.warn("[CORE-04][SEARCH][SQL_ERROR] Loi truy van danh sach mac dinh: {}", e.getMessage());
            }
        } else {
            // LỖ HỔNG 1: SQL INJECTION (Nối chuỗi trực tiếp phục vụ Lab)
            sql = "SELECT id, name, description, price FROM products WHERE name LIKE '%" + keyword + "%'";
            model.addAttribute("sql", sql);

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
                if (products.isEmpty()) {
                    log.info("[CORE-04][SEARCH][NOT_FOUND] Tu khoa='{}' -> Khong tim thay san pham nao (0 ket qua)", keyword);
                } else {
                    log.info("[CORE-04][SEARCH][FOUND] Tu khoa='{}' -> Tim thay {} san pham", keyword, products.size());
                }
            } catch (Exception e) {
                sqlError = e.getMessage();
                log.warn("[CORE-04][SEARCH][SQL_ERROR] Tu khoa='{}' -> Loi SQL: {}", keyword, e.getMessage());
            }
        }

        model.addAttribute("products", products);
        model.addAttribute("sqlError", sqlError);
        return "search";
    }

    // Hỗ trợ điều hướng đường dẫn dạng /products/{id} tương thích với /product?id=...
    @GetMapping("/products/{id}")
    public String productDetailByPath(@PathVariable("id") String id,
                                      HttpSession session,
                                      HttpServletRequest request,
                                      Model model) {
        return productDetail(id, session, request, model);
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

            // Lấy thông tin sản phẩm (Nối chuỗi id phục vụ Lab SQLi)
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
            if (product != null) {
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
                log.info("[CORE-06][READ][FOUND] Xem chi tiet san pham (vulnerable) id='{}' (name='{}') - So binh luan hien co: {}",
                        id, product.getName(), comments.size());
            } else {
                log.warn("[CORE-06][READ][NOT_FOUND] San pham khong ton tai (vulnerable): id='{}'", id);
            }
        } catch (Exception e) {
            log.warn("[CORE-06][READ][SQL_ERROR] Loi truy van chi tiet san pham id='{}': {}", id, e.getMessage());
            model.addAttribute("error", "Lỗi CSDL: " + e.getMessage());
        }

        model.addAttribute("product", product);
        model.addAttribute("comments", comments);
        return "product";
    }

    // Gửi bình luận sản phẩm (LỖ HỔNG STORED XSS & SQLi)
    @PostMapping({"/product", "/product.php"})
    public String addComment(@RequestParam(name = "product_id", defaultValue = "") String productId,
                             @RequestParam(name = "author", defaultValue = "") String author,
                             @RequestParam(name = "content", defaultValue = "") String content,
                             HttpSession session,
                             HttpServletRequest request,
                             RedirectAttributes redirectAttributes) {
        User sessionUser = resolveSessionUser(session, request);
        String resolvedAuthor = (author == null || author.trim().isEmpty())
                ? ((sessionUser != null && sessionUser.getUsername() != null && !sessionUser.getUsername().isBlank())
                    ? sessionUser.getUsername() : "Khách hàng")
                : author;

        log.info("[CORE-06][WRITE][REQUEST] Nhan yeu cau gui binh luan (vulnerable): product_id='{}', author='{}'",
                productId, resolvedAuthor);

        if (productId == null || productId.trim().isEmpty()) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan - Ma san pham rong");
            redirectAttributes.addFlashAttribute("commentError", "Mã sản phẩm không hợp lệ!");
            return "redirect:/";
        }

        if (content == null || content.trim().isEmpty()) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='{}' - Noi dung rong hoac chi chua khoang trang",
                    productId);
            redirectAttributes.addFlashAttribute("commentError", "Nội dung bình luận không được để trống hoặc chỉ chứa khoảng trắng!");
            return "redirect:/product?id=" + productId;
        }

        if (resolvedAuthor.trim().length() > 50) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='{}' - Ten tac gia vuot qua 50 ky tu (len={})",
                    productId, resolvedAuthor.trim().length());
            redirectAttributes.addFlashAttribute("commentError", "Tên người bình luận không được vượt quá 50 ký tự!");
            return "redirect:/product?id=" + productId;
        }

        if (content.trim().length() > 1000) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='{}' - Noi dung vuot qua 1000 ky tu (len={})",
                    productId, content.trim().length());
            redirectAttributes.addFlashAttribute("commentError", "Nội dung bình luận không được vượt quá 1000 ký tự!");
            return "redirect:/product?id=" + productId;
        }

        try (Connection conn = dbConfig.getConnection();
             Statement stmt = conn.createStatement()) {

            // LƯU TRỰC TIẾP VÀO DATABASE MÀ KHÔNG SANITIZE / ENCODE (Phục vụ Lab Stored XSS & Insert SQLi)
            String insertSql = "INSERT INTO comments (product_id, author, content) VALUES (" +
                    productId + ", '" + resolvedAuthor + "', '" + content + "')";
            int rowsAffected = stmt.executeUpdate(insertSql);
            if (rowsAffected > 0) {
                log.info("[CORE-06][WRITE][SAVED] Luu binh luan thanh cong vao DB (vulnerable): product_id='{}', author='{}', rowsAffected={}",
                        productId, resolvedAuthor, rowsAffected);
                redirectAttributes.addFlashAttribute("commentSuccess", "Gửi bình luận đánh giá thành công!");
            } else {
                log.warn("[CORE-06][WRITE][DB_ERROR] Khong co ban ghi nao duoc luu cho product_id='{}' (rowsAffected=0)", productId);
                redirectAttributes.addFlashAttribute("commentError", "Không thể lưu bình luận vào cơ sở dữ liệu!");
            }
        } catch (Exception e) {
            log.error("[CORE-06][WRITE][DB_ERROR] Luu binh luan that bai cho product_id='{}' - Loi DB: {}", productId, e.getMessage());
            redirectAttributes.addFlashAttribute("commentError", "Không thể lưu bình luận: Sản phẩm không tồn tại hoặc dữ liệu không hợp lệ!");
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

        if (username == null || username.trim().isEmpty()) {
            session.removeAttribute("user");
            clearVulnerableSessionCookie(response);
            model.addAttribute("user", null);
            model.addAttribute("message", "Vui lòng nhập tên đăng nhập!");
            log.warn("[CORE-07][AUTH][VALIDATION_FAILED] Dang nhap that bai (vulnerable) - Ten dang nhap rong");
            return "login";
        }

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
                log.info("[CORE-07][AUTH][SUCCESS] Dang nhap thanh cong (vulnerable) cho user='{}' (role='{}')",
                        user.getUsername(), user.getRole());

                return "redirect:/index.php";
            } else {
                session.removeAttribute("user");
                clearVulnerableSessionCookie(response);
                model.addAttribute("user", null);
                model.addAttribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!");
                log.warn("[CORE-07][AUTH][INVALID_CREDENTIALS] Dang nhap sai thong tin (vulnerable) cho username='{}'", username);
                return "login";
            }
        } catch (Exception e) {
            session.removeAttribute("user");
            clearVulnerableSessionCookie(response);
            model.addAttribute("user", null);
            model.addAttribute("message", "Lỗi truy vấn SQL: " + e.getMessage());
            log.error("[CORE-07][VULNERABLE][SQL_ERROR] Loi truy van dang nhap cho username='{}': {}", username, e.getMessage());
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
