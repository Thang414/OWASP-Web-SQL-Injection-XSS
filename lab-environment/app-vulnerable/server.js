const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 8080;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Cấu hình Session (KHÔNG bật HttpOnly -> phục vụ demo XSS cướp session)
app.use(session({
    secret: 'vulnerable_secret_key_123',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: false,
        maxAge: 3600000
    }
}));

// Middleware gắn thông tin người dùng từ session
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// 1. Trang chủ danh sách sản phẩm (hỗ trợ cả / và /index.php)
app.get(['/', '/index.php'], async (req, res) => {
    try {
        // Thiết lập Cookie phiên thông thường (KHÔNG cờ HttpOnly -> XSS đọc được)
        if (req.session.user && !req.cookies.session_token) {
            res.cookie('session_token', Buffer.from(req.session.user.username + '_secret_token_123').toString('base64'), {
                maxAge: 3600000,
                httpOnly: false,
                path: '/'
            });
        }

        const [products] = await db.query('SELECT * FROM products');
        res.render('index', { products });
    } catch (err) {
        console.error('Lỗi truy vấn sản phẩm:', err);
        res.status(500).send('Lỗi cơ sở dữ liệu: ' + err.message);
    }
});

// 2. Tìm kiếm sản phẩm (LỖ HỔNG SQL INJECTION + REFLECTED XSS)
app.get(['/search', '/search.php'], async (req, res) => {
    const keyword = req.query.keyword || '';
    
    // LỖ HỔNG 1: SQL INJECTION (Ghép chuỗi trực tiếp vào câu lệnh SELECT)
    const sql = `SELECT id, name, description, price FROM products WHERE name LIKE '%${keyword}%'`;
    
    let products = [];
    let sqlError = null;

    if (keyword !== '') {
        try {
            const [rows] = await db.query(sql);
            products = Array.isArray(rows[0]) ? rows[0] : rows;
        } catch (err) {
            sqlError = err.message;
        }
    }

    res.render('search', {
        keyword,
        sql,
        products,
        sqlError
    });
});

// 3. Chi tiết sản phẩm & Đánh giá (LỖ HỔNG STORED XSS)
app.get(['/product', '/product.php'], async (req, res) => {
    const id = req.query.id || 1;
    try {
        const [products] = await db.query(`SELECT * FROM products WHERE id = ${id}`);
        const product = products[0] || null;

        const [comments] = await db.query(`SELECT * FROM comments WHERE product_id = ${id} ORDER BY id DESC`);

        res.render('product', {
            product,
            comments,
            productId: id
        });
    } catch (err) {
        console.error('Lỗi lấy chi tiết sản phẩm:', err);
        res.status(500).send('Lỗi cơ sở dữ liệu: ' + err.message);
    }
});

// Gửi bình luận sản phẩm (LỖ HỔNG STORED XSS: Không sanitize input, lưu thẳng mã HTML/JS)
app.post(['/product', '/product.php'], async (req, res) => {
    const productId = req.query.id || req.body.product_id || 1;
    const author = req.body.author || 'Ẩn danh';
    const content = req.body.content || '';

    try {
        // LỖ HỔNG SQLi + STORED XSS: Ghép chuỗi trực tiếp khi INSERT
        const insertSql = `INSERT INTO comments (product_id, author, content) VALUES ('${productId}', '${author}', '${content}')`;
        await db.query(insertSql);
        res.redirect(`/product?id=${productId}`);
    } catch (err) {
        console.error('Lỗi thêm bình luận:', err);
        res.status(500).send('Lỗi thêm bình luận: ' + err.message);
    }
});

// 4. Đăng nhập (LỖ HỔNG SQL INJECTION AUTHENTICATION BYPASS)
app.get(['/login', '/login.php'], (req, res) => {
    res.render('login', { message: null });
});

app.post(['/login', '/login.php'], async (req, res) => {
    const username = req.body.username || '';
    const password = req.body.password || '';

    // LỖ HỔNG SQL INJECTION: Ghép chuỗi câu truy vấn
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    console.log('[DEBUG SQL VULNERABLE LOGIN]:', sql);

    try {
        const [rows] = await db.query(sql);
        const user = Array.isArray(rows[0]) ? rows[0][0] : rows[0];

        if (user) {
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role,
                full_name: user.full_name
            };

            // Thiết lập Cookie KHÔNG có cờ HttpOnly -> Dễ bị cướp qua XSS
            res.cookie('session_token', Buffer.from(user.username + '_token_secret_auth').toString('base64'), {
                maxAge: 3600000,
                httpOnly: false,
                path: '/'
            });

            return res.redirect('/index.php');
        } else {
            return res.render('login', { message: 'Tên đăng nhập hoặc mật khẩu không chính xác!' });
        }
    } catch (err) {
        console.error('Lỗi đăng nhập:', err);
        return res.render('login', { message: 'Lỗi truy vấn SQL: ' + err.message });
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
    console.log(`🚀 [VULNERABLE APP] Server Node.js đang chạy tại cổng http://localhost:${PORT}`);
});
