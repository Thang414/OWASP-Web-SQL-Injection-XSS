<?php
$host = getenv('DB_HOST') ?: 'db';
$db   = getenv('DB_NAME') ?: 'ecommerce_db';
$user = getenv('DB_USER') ?: 'db_user';
$pass = getenv('DB_PASS') ?: 'P@ssword123';
$charset = 'utf8mb4';

// GIẢI PHÁP PHÒNG THỦ: Sử dụng PHP Data Objects (PDO) với chế độ Parameterized Query
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // Buộc dùng prepared statement thực thụ từ MySQL engine
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    die("Lỗi kết nối cơ sở dữ liệu bảo mật: " . $e->getMessage());
}
?>
