const mysql = require('mysql2/promise');

const host = process.env.DB_HOST || 'db';
const database = process.env.DB_NAME || 'ecommerce_db';
const user = process.env.DB_USER || 'db_user';
const password = process.env.DB_PASS || 'P@ssword123';

// Kết nối MySQL pool với multipleStatements: true (dễ demo SQLi ghép chuỗi / comment)
const pool = mysql.createPool({
    host: host,
    user: user,
    password: password,
    database: database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    multipleStatements: true
});

module.exports = pool;
