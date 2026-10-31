<?php
require_once 'db.php';
session_start();

$keyword = $_GET['keyword'] ?? '';

// 1. PHÒNG THỦ SQL INJECTION: Sử dụng Prepared Statement với tham số :keyword
$stmt = $pdo->prepare("SELECT id, name, description, price FROM products WHERE name LIKE :keyword");
$stmt->execute([':keyword' => '%' . $keyword . '%']);
$results = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Kết quả Tìm kiếm - UTH E-Shop (Secured)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f4f6f9; }
        header { background: #28a745; color: white; padding: 15px 30px; }
        .container { max-width: 1000px; margin: 20px auto; padding: 0 20px; }
        .product-card { background: white; padding: 15px; margin-bottom: 15px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .price { color: #28a745; font-size: 18px; font-weight: bold; }
        .secure-note { background: #e8f5e9; color: #2e7d32; padding: 10px; border-radius: 4px; font-size: 13px; margin: 15px 0; }
        a { color: #28a745; }
    </style>
</head>
<body>

<header>
    <h2>🛒 UTH E-Shop - Kết Quả Tìm Kiếm (Secured)</h2>
</header>

<div class="container">
    <p><a href="index.php">⬅ Về Trang chủ</a></p>

    <!-- 2. PHÒNG THỦ REFLECTED XSS:
         Sử dụng htmlspecialchars() để mã hóa toàn bộ ký tự đặc biệt (<, >, ", ') thành HTML entities -->
    <h3>Kết quả tìm kiếm cho: <span><?= htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8') ?></span></h3>

    <div class="secure-note">
        🛡️ Ký tự nguy hiểm được mã hóa an toàn: Script không thể thực thi trên trình duyệt.
    </div>

    <?php if ($results && count($results) > 0): ?>
        <?php foreach ($results as $row): ?>
            <div class="product-card">
                <h4><?= htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') ?></h4>
                <p><?= htmlspecialchars($row['description'], ENT_QUOTES, 'UTF-8') ?></p>
                <div class="price"><?= number_format($row['price'], 0, ',', '.') ?> VNĐ</div>
            </div>
        <?php endforeach; ?>
    <?php else: ?>
        <p>Không tìm thấy sản phẩm nào phù hợp!</p>
    <?php endif; ?>
</div>

</body>
</html>
