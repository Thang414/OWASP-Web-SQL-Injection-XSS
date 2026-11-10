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
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
public class AppController {

    private static final Logger log = LoggerFactory.getLogger(AppController.class);
    private static final String SECURED_TOKEN_SUFFIX = "_secured_token_8081";
    public static final String GENERIC_SERVICE_ERROR_MSG =
            "Đã xảy ra lỗi trong quá trình xử lý yêu cầu hoặc dịch vụ tạm thời chưa sẵn sàng. Vui lòng thử lại sau.";

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
            log.info("[CORE-04][HOME] Hien thi trang chu (secured) - Tong so san pham: {}", products.size());
        } catch (Exception e) {
            log.error("[CORE-07][SECURED][DB_ERROR] Loi truy van danh sach san pham trang chu: {}", e.getMessage());
            model.addAttribute("error", GENERIC_SERVICE_ERROR_MSG);
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
        String cleanKeyword = (keyword == null) ? "" : keyword.trim();
        boolean isBlankKeyword = cleanKeyword.isEmpty();

        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);
        model.addAttribute("keyword", cleanKeyword);
        model.addAttribute("isBlankSearch", isBlankKeyword);

        List<Product> products = new ArrayList<>();

        if (isBlankKeyword) {
            // Trường hợp 3: Từ khóa rỗng hoặc chỉ chứa khoảng trắng -> Trả về toàn bộ danh sách sản phẩm mặc định
            String sql = "SELECT id, name, description, price FROM products";
            try (Connection conn = dbConfig.getConnection();
                 PreparedStatement pstmt = conn.prepareStatement(sql);
                 ResultSet rs = pstmt.executeQuery()) {

                while (rs.next()) {
                    products.add(new Product(
                            rs.getString("id"),
                            rs.getString("name"),
                            rs.getString("description"),
                            rs.getString("price"),
                            ""
                    ));
                }
                log.info("[CORE-04][SEARCH][BLANK_KEYWORD] Tu khoa rong hoac chi chua khoang trang (raw='{}') -> Tra ve toan bo {} san pham mac dinh",
                        keyword, products.size());
            } catch (Exception e) {
                log.error("[CORE-07][SECURED][DB_ERROR] Loi truy van danh sach mac dinh khi tim kiem: {}", e.getMessage());
                model.addAttribute("error", GENERIC_SERVICE_ERROR_MSG);
            }
        } else {
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
                if (products.isEmpty()) {
                    log.info("[CORE-04][SEARCH][NOT_FOUND] Tu khoa='{}' -> Khong tim thay san pham nao (0 ket qua)", cleanKeyword);
                } else {
                    log.info("[CORE-04][SEARCH][FOUND] Tu khoa='{}' -> Tim thay {} san pham", cleanKeyword, products.size());
                }
            } catch (Exception e) {
                log.error("[CORE-07][SECURED][DB_ERROR] Tu khoa='{}' -> Loi truy van tim kiem: {}", cleanKeyword, e.getMessage());
                model.addAttribute("error", GENERIC_SERVICE_ERROR_MSG);
            }
        }

        model.addAttribute("products", products);
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

    // 3. Chi tiết sản phẩm & Bình luận (Secured)
    @GetMapping({"/product", "/product.php"})
    public String productDetail(@RequestParam(name = "id", defaultValue = "1") String idStr,
                                HttpSession session,
                                HttpServletRequest request,
                                Model model) {
        User user = resolveSessionUser(session, request);
        model.addAttribute("user", user);

        int id = -1;
        try {
            if (idStr != null) {
                id = Integer.parseInt(idStr.trim());
            }
        } catch (NumberFormatException ignored) {
            id = -1;
        }

        model.addAttribute("productId", id > 0 ? id : idStr);
        Product product = null;
        List<Comment> comments = new ArrayList<>();

        if (id > 0) {
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
                if (product != null) {
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
                    log.info("[CORE-06][READ][FOUND] Xem chi tiet san pham (secured) id='{}' (name='{}') - So binh luan hien co: {}",
                            id, product.getName(), comments.size());
                } else {
                    log.warn("[CORE-06][READ][NOT_FOUND] San pham khong ton tai (secured): id='{}'", idStr);
                }
            } catch (Exception e) {
                log.error("[CORE-07][SECURED][DB_ERROR] Loi truy van chi tiet san pham id='{}': {}", idStr, e.getMessage());
                model.addAttribute("error", GENERIC_SERVICE_ERROR_MSG);
            }
        } else {
            log.warn("[CORE-06][READ][NOT_FOUND] San pham khong ton tai hoac ID khong hop le (secured): id='{}'", idStr);
        }

        model.addAttribute("product", product);
        model.addAttribute("comments", comments);
        return "product";
    }

    // Gửi bình luận (PHÒNG THỦ: PREPARED STATEMENT + VALIDATION)
    @PostMapping({"/product", "/product.php"})
    public String addComment(@RequestParam(name = "product_id", defaultValue = "") String productIdStr,
                             @RequestParam(name = "author", defaultValue = "") String author,
                             @RequestParam(name = "content", defaultValue = "") String content,
                             HttpSession session,
                             HttpServletRequest request,
                             RedirectAttributes redirectAttributes) {
        User sessionUser = resolveSessionUser(session, request);
        String cleanAuthor = (author == null || author.trim().isEmpty())
                ? ((sessionUser != null && sessionUser.getUsername() != null && !sessionUser.getUsername().isBlank())
                    ? sessionUser.getUsername() : "Khách hàng")
                : author.trim();

        log.info("[CORE-06][WRITE][REQUEST] Nhan yeu cau gui binh luan (secured): product_id='{}', author='{}'",
                productIdStr, cleanAuthor);

        if (productIdStr == null || productIdStr.trim().isEmpty()) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan - Ma san pham rong");
            redirectAttributes.addFlashAttribute("commentError", "Mã sản phẩm không hợp lệ!");
            return "redirect:/";
        }

        int productId;
        try {
            productId = Integer.parseInt(productIdStr.trim());
            if (productId <= 0) {
                throw new NumberFormatException("ID must be positive");
            }
        } catch (NumberFormatException e) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan - Ma san pham khong hop le: '{}'", productIdStr);
            redirectAttributes.addFlashAttribute("commentError", "Mã sản phẩm không hợp lệ!");
            return "redirect:/product?id=" + productIdStr;
        }

        String cleanContent = (content == null) ? "" : content.trim();
        if (cleanContent.isEmpty()) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='{}' - Noi dung rong hoac chi chua khoang trang",
                    productId);
            redirectAttributes.addFlashAttribute("commentError", "Nội dung bình luận không được để trống hoặc chỉ chứa khoảng trắng!");
            return "redirect:/product?id=" + productId;
        }

        if (cleanAuthor.length() > 50) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='{}' - Ten tac gia vuot qua 50 ky tu (len={})",
                    productId, cleanAuthor.length());
            redirectAttributes.addFlashAttribute("commentError", "Tên người bình luận không được vượt quá 50 ký tự!");
            return "redirect:/product?id=" + productId;
        }

        if (cleanContent.length() > 1000) {
            log.warn("[CORE-06][WRITE][VALIDATION_FAILED] Tu choi luu binh luan cho product_id='{}' - Noi dung vuot qua 1000 ky tu (len={})",
                    productId, cleanContent.length());
            redirectAttributes.addFlashAttribute("commentError", "Nội dung bình luận không được vượt quá 1000 ký tự!");
            return "redirect:/product?id=" + productId;
        }

        // PHÒNG THỦ SQL INJECTION: PreparedStatement
        String sql = "INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)";
        try (Connection conn = dbConfig.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, productId);
            pstmt.setString(2, cleanAuthor);
            pstmt.setString(3, cleanContent);
            int rowsAffected = pstmt.executeUpdate();
            if (rowsAffected > 0) {
                log.info("[CORE-06][WRITE][SAVED] Luu binh luan thanh cong vao DB (secured): product_id='{}', author='{}', rowsAffected={}",
                        productId, cleanAuthor, rowsAffected);
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

        String cleanUser = (username == null) ? "" : username.trim();
        String cleanPass = (password == null) ? "" : password.trim();

        if (cleanUser.isEmpty() || cleanPass.isEmpty()) {
            session.removeAttribute("user");
            clearSecuredSessionCookie(response);
            model.addAttribute("user", null);
            model.addAttribute("message", "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu!");
            log.warn("[CORE-07][AUTH][VALIDATION_FAILED] Dang nhap that bai (secured) - Thieu username hoac password");
            return "login";
        }

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
                    log.info("[CORE-07][AUTH][SUCCESS] Dang nhap thanh cong (secured) cho user='{}' (role='{}')",
                            user.getUsername(), user.getRole());

                    return "redirect:/index.php";
                } else {
                    session.removeAttribute("user");
                    clearSecuredSessionCookie(response);
                    model.addAttribute("user", null);
                    model.addAttribute("message", "Tên đăng nhập hoặc mật khẩu không chính xác!");
                    log.warn("[CORE-07][AUTH][INVALID_CREDENTIALS] Dang nhap sai thong tin (secured) cho username='{}'", cleanUser);
                    return "login";
                }
            }
        } catch (Exception e) {
            session.removeAttribute("user");
            clearSecuredSessionCookie(response);
            model.addAttribute("user", null);
            log.error("[CORE-07][SECURED][DB_ERROR] Loi he thong khi xac thuc dang nhap cho user='{}': {}", cleanUser, e.getMessage());
            model.addAttribute("message", GENERIC_SERVICE_ERROR_MSG);
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
