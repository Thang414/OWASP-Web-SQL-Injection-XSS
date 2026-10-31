const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 8081;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// PHÒNG THỦ LỚP HTTP RESPONSE HEADER:
app.use((req, res, next) => {
    // 1. Chống Clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    // 2. Chống MIME-sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // 3. Content Security Policy (CSP): Chặn script inline và script lạ từ bên ngoài
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline';");
    next();
});

// Cấu hình Session AN TOÀN: BẬT CỜ HTTPONLY & SAMESITE
app.use(session({
    secret: 'secured_super_secret_key_8081_auth',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // BẢO MẬT: Ngăn Javascript truy cập Cookie
        sameSite: 'lax',
        maxAge: 3600000
    }
}));

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// 1. Trang chủ danh sách sản phẩm (Secured)
app.get(['/', '/index.php'], async (req, res) => {
    try {
        if (req.session.user && !req.cookies.session_token) {
            // Cookie bảo mật với cờ HttpOnly
            res.cookie('session_token', Buffer.from(req.session.user.username + '_secured_token_8081').toString('base64'), {
                maxAge: 3600000,
                httpOnly: true,
                sameSite: 'lax',
                path: '/'
            });
        }

        const [products] = await db.execute('SELECT * FROM products');
        res.render('index', { products });
    } catch (err) {
        console.error('Lỗi truy vấn sản phẩm:', err);
        res.status(500).send('Lỗi cơ sở dữ liệu: ' + err.message);
    }
});

// 2. Tìm kiếm sản phẩm (PHÒNG THỦ: PREPARED STATEMENT + OUTPUT ENCODING)
app.get(['/search', '/search.php'], async (req, res) => {
    const keyword = (req.query.keyword || '').trim();
    let products = [];

    if (keyword !== '') {
        try {
            // PHÒNG THỦ SQL INJECTION: Sử dụng Prepared Statement với tham số hóa ?
            const [rows] = await db.execute(
                'SELECT id, name, description, price FROM products WHERE name LIKE ?',
                [`%${keyword}%`]
            );
            products = rows;
        } catch (err) {
            console.error('Lỗi tìm kiếm:', err);
        }
    }

    res.render('search', {
        keyword,
        products
    });
});

// 3. Chi tiết sản phẩm & Bình luận (Secured)
app.get(['/product', '/product.php'], async (req, res) => {
    const id = parseInt(req.query.id, 10) || 1;
    try {
        // PHÒNG THỦ SQL INJECTION: Tham số hóa id
        const [products] = await db.execute('SELECT * FROM products WHERE id = ?', [id]);
        const product = products[0] || null;

        const [comments] = await db.execute('SELECT * FROM comments WHERE product_id = ? ORDER BY id DESC', [id]);

        res.render('product', {
            product,
            comments,
            productId: id
        });
    } catch (err) {
        console.error('Lỗi chi tiết sản phẩm:', err);
        res.status(500).send('Lỗi cơ sở dữ liệu: ' + err.message);
    }
});

// Gửi bình luận (PHÒNG THỦ: PREPARED STATEMENT + SANITIZATION)
app.post(['/product', '/product.php'], async (req, res) => {
    const productId = parseInt(req.query.id || req.body.product_id, 10) || 1;
    const author = (req.body.author || 'Ẩn danh').trim().substring(0, 50);
    const content = (req.body.content || '').trim();

    if (content.length > 0) {
        try {
            // PHÒNG THỦ SQL INJECTION: Dùng Prepared Statement
            await db.execute(
                'INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)',
                [productId, author, content]
            );
        } catch (err) {
            console.error('Lỗi lưu bình luận:', err);
        }
    }

    res.redirect(`/product?id=${productId}`);
});

// 4. Đăng nhập (PHÒNG THỦ: PREPARED STATEMENT)
app.get(['/login', '/login.php'], (req, res) => {
    res.render('login', { message: null });
});

app.post(['/login', '/login.php'], async (req, res) => {
    const username = (req.body.username || '').trim();
    const password = (req.body.password || '').trim();

    try {
        // PHÒNG THỦ SQL INJECTION: Prepared Statement tách biệt hoàn toàn mã SQL và tham số người dùng
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            [username, password]
        );
        const user = rows[0];

        if (user) {
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role,
                full_name: user.full_name
            };

            // Thiết lập Cookie an toàn: BẬT CỜ HTTPONLY & SAMESITE
            res.cookie('session_token', Buffer.from(user.username + '_secured_token_8081').toString('base64'), {
                maxAge: 3600000,
                httpOnly: true,
                sameSite: 'lax',
                path: '/'
            });

            return res.redirect('/index.php');
        } else {
            return res.render('login', { message: 'Tên đăng nhập hoặc mật khẩu không chính xác!' });
        }
    } catch (err) {
        console.error('Lỗi đăng nhập:', err);
        return res.render('login', { message: 'Lỗi hệ thống: ' + err.message });
    }
});

// 5. Đăng xuất
app.get(['/logout', '/logout.php'], (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('session_token');
        res.redirect('/login.php');
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ [SECURED APP] Server Node.js đang chạy tại cổng http://localhost:${PORT}`);
});
