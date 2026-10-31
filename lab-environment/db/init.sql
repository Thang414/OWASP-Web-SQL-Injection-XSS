-- Khởi tạo cơ sở dữ liệu mẫu cho ứng dụng Thương mại điện tử
CREATE DATABASE IF NOT EXISTS ecommerce_db;
USE ecommerce_db;

-- 1. Bảng người dùng (Chứa tài khoản admin & khách hàng)
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'customer',
    credit_card VARCHAR(30)
);

-- Thêm dữ liệu tài khoản mẫu
INSERT INTO users (username, password, full_name, role, credit_card) VALUES
('admin', 'admin123_super_secret', 'Quản Trị Viên Hệ Thống', 'admin', '4111-2222-3333-4444'),
('manager', 'manager@2026', 'Trưởng Phòng Kinh Doanh', 'manager', '4555-6666-7777-8888'),
('nguyenvana', 'pass123456', 'Nguyễn Văn A', 'customer', '9704-1111-2222-3333'),
('tranthib', 'passwordB123', 'Trần Thị B', 'customer', '9704-4444-5555-6666');

-- 2. Bảng sản phẩm TMĐT
DROP TABLE IF EXISTS products;
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    category VARCHAR(50)
);

INSERT INTO products (name, description, price, category) VALUES
('iPhone 15 Pro Max', 'Điện thoại thông minh Apple 256GB Titan tự nhiên', 29990000.00, 'Điện thoại'),
('Samsung Galaxy S24 Ultra', 'Flagship AI Phone đỉnh cao Snapdragon 8 Gen 3', 27490000.00, 'Điện thoại'),
('Laptop Dell XPS 15', 'Laptop cao cấp Intel Core i7, 16GB RAM, 512GB SSD', 35000000.00, 'Máy tính'),
('MacBook Air M2', 'Thiết kế siêu mỏng nhẹ, pin 18 tiếng, Apple Silicon M2', 22500000.00, 'Máy tính'),
('Tai nghe Sony WH-1000XM5', 'Tai nghe chống ồn chủ động cao cấp', 7990000.00, 'Phụ kiện');

-- 3. Bảng bình luận/đánh giá sản phẩm (Dùng để demo Stored XSS)
DROP TABLE IF EXISTS comments;
CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT NOT NULL,
    author VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

INSERT INTO comments (product_id, author, content) VALUES
(1, 'Nguyễn Văn A', 'Sản phẩm dùng rất mượt, camera chụp đêm rất đỉnh!'),
(1, 'Trần Thị B', 'Pin trâu, dùng cả ngày thoải mái.'),
(2, 'Lê Văn C', 'Màn hình hiển thị siêu đẹp, tính năng AI dịch rất tiện lợi.');
