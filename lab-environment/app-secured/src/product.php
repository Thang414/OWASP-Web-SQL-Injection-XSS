<?php
require_once 'db.php';
session_start();

$product_id = isset($_GET['id']) ? intval($_GET['id']) : 1;

// Xử lý gửi bình luận (ĐÃ ÁP DỤNG PHÒNG THỦ)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Sanitize & Validate dữ liệu đầu vào
    $author  = trim($_POST['author'] ?? 'Ẩn danh');
    $content = trim($_POST['content'] ?? '');

    if (!empty($content)) {
        // 2. PHÒNG THỦ SQL INJECTION: Dùng Prepared Statement
        $stmt_insert = $pdo->prepare("INSERT INTO comments (product_id, author, content) VALUES (:product_id, :author, :content)");
        $stmt_insert->execute([
            ':product_id' => $product_id,
            ':author'     => $author,
            ':content'    => $content
        ]);
    }
    header("Location: product.php?id=" . $product_id);
    exit();
}

// Lấy thông tin sản phẩm (Prepared Statement)
$stmt_prod = $pdo->prepare("SELECT * FROM products WHERE id = :id");
$stmt_prod->execute([':id' => $product_id]);
$product = $stmt_prod->fetch();

// Lấy danh sách bình luận (Prepared Statement)
$stmt_cmt = $pdo->prepare("SELECT * FROM comments WHERE product_id = :product_id ORDER BY id DESC");
$stmt_cmt->execute([':product_id' => $product_id]);
$comments = $stmt_cmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title><?= $product ? htmlspecialchars($product['name'], ENT_QUOTES, 'UTF-8') : 'Chi tiết sản phẩm' ?> - UTH E-Shop (Secured)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f4f6f9; }
        header { background: #28a745; color: white; padding: 15px 30px; }
        .container { max-width: 900px; margin: 20px auto; padding: 0 20px; }
        .product-detail { background: white; padding: 25px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 25px; }
        .price { color: #28a745; font-size: 22px; font-weight: bold; margin: 15px 0; }
        .comment-section { background: white; padding: 25px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .comment-card { border-bottom: 1px solid #eee; padding: 12px 0; }
        .comment-author { font-weight: bold; color: #2c3e50; }
        .comment-time { font-size: 12px; color: #7f8c8d; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        a { color: #28a745; }
    </style>
</head>
<body>

<header>
    <h2>🛒 UTH E-Shop - Chi Tiết Sản Phẩm & Đánh Giá (Secured)</h2>
</header>

<div class="container">
    <p><a href="index.php">⬅ Về Danh sách sản phẩm</a></p>

    <?php if ($product): ?>
        <div class="product-detail">
            <h2><?= htmlspecialchars($product['name'], ENT_QUOTES, 'UTF-8') ?></h2>
            <p><strong>Danh mục:</strong> <?= htmlspecialchars($product['category'], ENT_QUOTES, 'UTF-8') ?></p>
            <div class="price"><?= number_format($product['price'], 0, ',', '.') ?> VNĐ</div>
            <p><?= htmlspecialchars($product['description'], ENT_QUOTES, 'UTF-8') ?></p>
        </div>

        <div class="comment-section">
            <h3>Đánh giá từ khách hàng</h3>

            <form method="POST">
                <div class="form-group">
                    <label>Tên của bạn:</label>
                    <input type="text" name="author" value="<?= htmlspecialchars($_SESSION['username'] ?? 'Khách hàng', ENT_QUOTES, 'UTF-8') ?>" required>
                </div>
                <div class="form-group">
                    <label>Nội dung bình luận / Đánh giá:</label>
                    <textarea name="content" rows="3" placeholder="Nhập cảm nhận an toàn..." required></textarea>
                </div>
                <button type="submit">Gửi Bình Luận</button>
            </form>

            <hr style="margin: 25px 0; border: 0; border-top: 1px solid #eee;">

            <h4>Các bình luận đã đăng:</h4>
            <?php if ($comments && count($comments) > 0): ?>
                <?php foreach ($comments as $cmt): ?>
                    <div class="comment-card">
                        <div class="comment-author">
                            <?= htmlspecialchars($cmt['author'], ENT_QUOTES, 'UTF-8') ?> 
                            <span class="comment-time">(<?= htmlspecialchars($cmt['created_at'], ENT_QUOTES, 'UTF-8') ?>)</span>:
                        </div>
                        <!-- 3. PHÒNG THỦ STORED XSS:
                             Bắt buộc dùng htmlspecialchars() khi render nội dung ra HTML.
                             Mọi thẻ <script> sẽ biến thành &lt;script&gt; và chỉ hiển thị dưới dạng văn bản bình thường! -->
                        <div class="comment-body"><?= htmlspecialchars($cmt['content'], ENT_QUOTES, 'UTF-8') ?></div>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p>Chưa có bình luận nào cho sản phẩm này.</p>
            <?php endif; ?>
        </div>
    <?php else: ?>
        <p>Sản phẩm không tồn tại!</p>
    <?php endif; ?>
</div>

</body>
</html>
