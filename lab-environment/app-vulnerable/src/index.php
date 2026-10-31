<?php
require_once 'db.php';
session_start();

// Thiết lập Cookie phiên thông thường (KHÔNG bật HttpOnly -> Dễ bị XSS cướp cookie)
if (!isset($_COOKIE['session_token']) && isset($_SESSION['username'])) {
    setcookie("session_token", base64_encode($_SESSION['username'] . "_secret_token_123"), time() + 3600, "/");
}

$sql = "SELECT * FROM products";
$result = $conn->query($sql);
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Cửa Hàng TMĐT UTH (Vulnerable App)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f4f6f9; }
        header { background: #d9534f; color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        .banner-warning { background: #ffebee; color: #c62828; padding: 10px 30px; font-weight: bold; border-bottom: 1px solid #ffcdd2; }
        .container { max-width: 1000px; margin: 20px auto; padding: 0 20px; }
        .search-box { margin-bottom: 25px; display: flex; gap: 10px; }
        .search-box input { flex: 1; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 4px; }
        .search-box button { padding: 10px 20px; background: #d9534f; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
        .product-card { background: white; padding: 15px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .price { color: #d9534f; font-size: 18px; font-weight: bold; }
        a { color: #337ab7; text-decoration: none; }
        .user-info { font-size: 14px; }
    </style>
</head>
<body>

<header>
    <h2>🛒 UTH E-Shop (Phiên Bản Demo Lỗi Bảo Mật - Cổng 8080)</h2>
    <div class="user-info">
        <?php if (isset($_SESSION['username'])): ?>
            Xin chào, <strong><?= $_SESSION['username'] ?> (Quyền: <?= $_SESSION['role'] ?>)</strong> | 
            <a href="logout.php" style="color: white; text-decoration: underline;">Đăng xuất</a>
        <?php else: ?>
            <a href="login.php" style="color: white; text-decoration: underline;">Đăng nhập</a>
        <?php endif; ?>
    </div>
</header>

<div class="banner-warning">
    ⚠️ CẢNH BÁO LAB: Ứng dụng này đang chứa lỗ hổng bảo mật SQL Injection và XSS phục vụ nghiên cứu học phần An ninh mạng UTH.
</div>

<div class="container">
    <!-- Form tìm kiếm dính Reflected XSS & SQL Injection -->
    <form class="search-box" action="search.php" method="GET">
        <input type="text" name="keyword" placeholder="Nhập tên sản phẩm cần tìm kiếm (VD: iPhone, Laptop...)...">
        <button type="submit">Tìm kiếm</button>
    </form>

    <h3>Danh sách Sản phẩm Nổi bật</h3>
    <div class="product-grid">
        <?php while ($row = $result->fetch_assoc()): ?>
            <div class="product-card">
                <h4><a href="product.php?id=<?= $row['id'] ?>"><?= $row['name'] ?></a></h4>
                <p><?= $row['description'] ?></p>
                <div class="price"><?= number_format($row['price'], 0, ',', '.') ?> VNĐ</div>
                <p><a href="product.php?id=<?= $row['id'] ?>">👉 Xem chi tiết & Đánh giá</a></p>
            </div>
        <?php endwhile; ?>
    </div>
</div>

</body>
</html>
