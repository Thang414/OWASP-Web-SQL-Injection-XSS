<?php
require_once 'db.php';
session_start();

// PHÒNG THỦ LỚP HTTP HEADER:
// 1. Chống Clickjacking
header("X-Frame-Options: DENY");
// 2. Chống MIME-sniffing
header("X-Content-Type-Options: nosniff");
// 3. Content Security Policy (CSP): Chặn hoàn toàn script inline và script từ domain lạ
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline';");

// Thiết lập Cookie an toàn: BẬT CỜ HTTPONLY (Javascript không thể đọc trộm cookie này)
if (!isset($_COOKIE['session_token']) && isset($_SESSION['username'])) {
    setcookie("session_token", base64_encode($_SESSION['username'] . "_secured_token_8081"), [
        'expires'  => time() + 3600,
        'path'     => '/',
        'httponly' => true, // BẢO MẬT: Chống đánh cắp cookie qua XSS
        'samesite' => 'Lax'
    ]);
}

$stmt = $pdo->query("SELECT * FROM products");
$products = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Cửa Hàng TMĐT UTH (Secured App - Cổng 8081)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f4f6f9; }
        header { background: #28a745; color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        .banner-success { background: #e8f5e9; color: #2e7d32; padding: 10px 30px; font-weight: bold; border-bottom: 1px solid #c8e6c9; }
        .container { max-width: 1000px; margin: 20px auto; padding: 0 20px; }
        .search-box { margin-bottom: 25px; display: flex; gap: 10px; }
        .search-box input { flex: 1; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 4px; }
        .search-box button { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
        .product-card { background: white; padding: 15px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .price { color: #28a745; font-size: 18px; font-weight: bold; }
        a { color: #28a745; text-decoration: none; }
        .user-info { font-size: 14px; }
    </style>
</head>
<body>

<header>
    <h2>🛡️ UTH E-Shop (Phiên Bản ĐÃ VÁ LỖ HỔNG - Cổng 8081)</h2>
    <div class="user-info">
        <?php if (isset($_SESSION['username'])): ?>
            Xin chào, <strong><?= htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8') ?> (<?= htmlspecialchars($_SESSION['role'], ENT_QUOTES, 'UTF-8') ?>)</strong> | 
            <a href="logout.php" style="color: white; text-decoration: underline;">Đăng xuất</a>
        <?php else: ?>
            <a href="login.php" style="color: white; text-decoration: underline;">Đăng nhập</a>
        <?php endif; ?>
    </div>
</header>

<div class="banner-success">
    ✅ HỆ THỐNG AN TOÀN: Đã áp dụng Prepared Statements (chống SQLi), Output Encoding & HttpOnly Cookie + CSP (chống XSS).
</div>

<div class="container">
    <form class="search-box" action="search.php" method="GET">
        <input type="text" name="keyword" placeholder="Nhập tên sản phẩm cần tìm...">
        <button type="submit">Tìm kiếm</button>
    </form>

    <h3>Danh sách Sản phẩm</h3>
    <div class="product-grid">
        <?php foreach ($products as $p): ?>
            <div class="product-card">
                <h4><a href="product.php?id=<?= $p['id'] ?>"><?= htmlspecialchars($p['name'], ENT_QUOTES, 'UTF-8') ?></a></h4>
                <p><?= htmlspecialchars($p['description'], ENT_QUOTES, 'UTF-8') ?></p>
                <div class="price"><?= number_format($p['price'], 0, ',', '.') ?> VNĐ</div>
                <p><a href="product.php?id=<?= $p['id'] ?>">👉 Xem chi tiết & Đánh giá</a></p>
            </div>
        <?php endforeach; ?>
    </div>
</div>

</body>
</html>
