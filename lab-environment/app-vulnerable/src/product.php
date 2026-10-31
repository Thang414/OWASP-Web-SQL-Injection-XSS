<?php
require_once 'db.php';
session_start();

$product_id = isset($_GET['id']) ? intval($_GET['id']) : 1;

// Xử lý gửi bình luận (LỖ HỔNG STORED XSS)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $author  = $_POST['author'] ?? 'Ẩn danh';
    $content = $_POST['content'] ?? '';

    // LƯU TRỰC TIẾP VÀO CƠ SỞ DỮ LIỆU MÀ KHÔNG LỌC HOẶC SANITIZE MÃ HTML/JS
    $sql_insert = "INSERT INTO comments (product_id, author, content) VALUES ('$product_id', '$author', '$content')";
    $conn->query($sql_insert);
    header("Location: product.php?id=" . $product_id);
    exit();
}

// Lấy thông tin sản phẩm
$product_sql = "SELECT * FROM products WHERE id = $product_id";
$product_res = $conn->query($product_sql);
$product = $product_res ? $product_res->fetch_assoc() : null;

// Lấy danh sách bình luận
$comment_sql = "SELECT * FROM comments WHERE product_id = $product_id ORDER BY id DESC";
$comment_res = $conn->query($comment_sql);
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title><?= $product ? $product['name'] : 'Chi tiết sản phẩm' ?> - UTH E-Shop (Vulnerable)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f4f6f9; }
        header { background: #d9534f; color: white; padding: 15px 30px; }
        .container { max-width: 900px; margin: 20px auto; padding: 0 20px; }
        .product-detail { background: white; padding: 25px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 25px; }
        .price { color: #d9534f; font-size: 22px; font-weight: bold; margin: 15px 0; }
        .comment-section { background: white; padding: 25px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .comment-card { border-bottom: 1px solid #eee; padding: 12px 0; }
        .comment-author { font-weight: bold; color: #2c3e50; }
        .comment-time { font-size: 12px; color: #7f8c8d; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 20px; background: #d9534f; color: white; border: none; border-radius: 4px; cursor: pointer; }
        a { color: #337ab7; }
    </style>
</head>
<body>

<header>
    <h2>🛒 UTH E-Shop - Chi Tiết Sản Phẩm & Đánh Giá</h2>
</header>

<div class="container">
    <p><a href="index.php">⬅ Về Danh sách sản phẩm</a></p>

    <?php if ($product): ?>
        <div class="product-detail">
            <h2><?= $product['name'] ?></h2>
            <p><strong>Danh mục:</strong> <?= $product['category'] ?></p>
            <div class="price"><?= number_format($product['price'], 0, ',', '.') ?> VNĐ</div>
            <p><?= $product['description'] ?></p>
        </div>

        <div class="comment-section">
            <h3>Đánh giá từ khách hàng</h3>

            <!-- Form gửi bình luận dính Stored XSS -->
            <form method="POST">
                <div class="form-group">
                    <label>Tên của bạn:</label>
                    <input type="text" name="author" value="<?= $_SESSION['username'] ?? 'Khách hàng' ?>" required>
                </div>
                <div class="form-group">
                    <label>Nội dung bình luận / Đánh giá:</label>
                    <textarea name="content" rows="3" placeholder="Nhập cảm nhận của bạn về sản phẩm..." required></textarea>
                </div>
                <button type="submit">Gửi Bình Luận</button>
            </form>

            <hr style="margin: 25px 0; border: 0; border-top: 1px solid #eee;">

            <h4>Các bình luận đã đăng:</h4>
            <?php if ($comment_res && $comment_res->num_rows > 0): ?>
                <?php while ($cmt = $comment_res->fetch_assoc()): ?>
                    <div class="comment-card">
                        <div class="comment-author"><?= $cmt['author'] ?> <span class="comment-time">(<?= $cmt['created_at'] ?>)</span>:</div>
                        <!-- LỖ HỔNG STORED XSS:
                             In nội dung comment ra giao diện trực tiếp mà không mã hóa HTML entities.
                             Nếu comment chứa mã <script> cướp cookie, bất kỳ ai xem trang này cũng sẽ bị kích hoạt mã độc! -->
                        <div class="comment-body"><?= $cmt['content'] ?></div>
                    </div>
                <?php endwhile; ?>
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
