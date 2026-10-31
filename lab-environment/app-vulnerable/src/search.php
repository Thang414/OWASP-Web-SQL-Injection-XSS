<?php
require_once 'db.php';
session_start();

$keyword = $_GET['keyword'] ?? '';

// LỖ HỔNG 1: SQL INJECTION (UNION-BASED)
// Ghép trực tiếp từ khóa vào câu lệnh SELECT
$sql = "SELECT id, name, description, price FROM products WHERE name LIKE '%$keyword%'";
$result = $conn->query($sql);
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Kết quả Tìm kiếm - UTH E-Shop (Vulnerable)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f4f6f9; }
        header { background: #d9534f; color: white; padding: 15px 30px; }
        .container { max-width: 1000px; margin: 20px auto; padding: 0 20px; }
        .product-card { background: white; padding: 15px; margin-bottom: 15px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .price { color: #d9534f; font-size: 18px; font-weight: bold; }
        .debug-sql { background: #2d3748; color: #a0aec0; padding: 10px; border-radius: 4px; font-family: monospace; margin: 15px 0; word-break: break-all; }
        a { color: #337ab7; }
    </style>
</head>
<body>

<header>
    <h2>🛒 UTH E-Shop - Kết Quả Tìm Kiếm</h2>
</header>

<div class="container">
    <p><a href="index.php">⬅ Về Trang chủ</a></p>

    <!-- LỖ HỔNG 2: REFLECTED XSS
         In trực tiếp giá trị $keyword từ URL ra màn hình mà KHÔNG qua htmlspecialchars() -->
    <h3>Kết quả tìm kiếm cho: <span><?= $keyword ?></span></h3>

    <div class="debug-sql">
        <strong>Câu truy vấn thực thi trên MySQL:</strong><br>
        <code><?= $sql ?></code>
    </div>

    <?php if ($result && $result->num_rows > 0): ?>
        <?php while ($row = $result->fetch_assoc()): ?>
            <div class="product-card">
                <h4><?= $row['name'] ?></h4>
                <p><?= $row['description'] ?></p>
                <div class="price"><?= is_numeric($row['price']) ? number_format($row['price'], 0, ',', '.') . ' VNĐ' : $row['price'] ?></div>
            </div>
        <?php endwhile; ?>
    <?php else: ?>
        <p>Không tìm thấy sản phẩm nào phù hợp!</p>
    <?php endif; ?>
</div>

</body>
</html>
