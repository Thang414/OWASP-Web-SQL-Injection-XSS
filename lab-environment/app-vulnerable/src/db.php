<?php
$host = getenv('DB_HOST') ?: 'db';
$db   = getenv('DB_NAME') ?: 'ecommerce_db';
$user = getenv('DB_USER') ?: 'db_user';
$pass = getenv('DB_PASS') ?: 'P@ssword123';

// Kết nối MySQLi truyền thống (Dễ phát sinh lỗi SQL Injection khi không dùng Parameterized)
$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Kết nối cơ sở dữ liệu thất bại: " . $conn->connect_error);
}
$conn->set_charset("utf8mb4");
?>
