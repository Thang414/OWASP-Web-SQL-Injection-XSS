<?php
require_once 'db.php';
session_start();

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    // GIẢI PHÁP PHÒNG THỦ SQL INJECTION: PREPARED STATEMENT (THAM SỐ HÓA TRUY VẤN)
    // Tách rời mã SQL và dữ liệu người dùng nhập vào.
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
    $stmt->execute([
        ':username' => $username,
        ':password' => $password
    ]);
    $user = $stmt->fetch();

    if ($user) {
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];

        // Cờ bảo mật cho Cookie
        setcookie("session_token", base64_encode($user['username'] . "_secured_token_8081"), [
            'expires'  => time() + 3600,
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        header("Location: index.php");
        exit();
    } else {
        $message = "Tên đăng nhập hoặc mật khẩu không chính xác!";
    }
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Đăng nhập - UTH E-Shop (Secured)</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); width: 380px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #28a745; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        .error { color: red; margin-bottom: 15px; }
        .verify-box { background: #e8f5e9; border: 1px solid #c8e6c9; color: #2e7d32; padding: 10px; margin-top: 15px; font-size: 13px; border-radius: 4px; }
    </style>
</head>
<body>

<div class="login-card">
    <h2 style="text-align: center; color: #28a745;">Đăng Nhập Bảo Mật</h2>
    
    <?php if ($message): ?>
        <div class="error"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <form method="POST" action="login.php">
        <div class="form-group">
            <label>Tên đăng nhập:</label>
            <input type="text" name="username" placeholder="Nhập username..." required>
        </div>
        <div class="form-group">
            <label>Mật khẩu:</label>
            <input type="password" name="password" placeholder="Nhập mật khẩu..." required>
        </div>
        <button type="submit">Đăng Nhập</button>
    </form>

    <div class="verify-box">
        🛡️ <strong>Kiểm thử lại phòng thủ (Bước 4):</strong><br>
        Nhập payload: <code>admin' -- </code><br>
        👉 Kết quả: Đăng nhập thất bại hoàn toàn vì database xử lý chuỗi trên như một username bình thường, không thể bypass xác thực.
    </div>

    <p style="text-align: center; margin-top: 15px;"><a href="index.php" style="color: #28a745;">⬅ Quay lại Trang chủ</a></p>
</div>

</body>
</html>
