#!/usr/bin/env bash
# Quy trình reset dữ liệu cơ sở dữ liệu mẫu cho lab (INFRA-06 / CORE-02 / CORE-03)
# Phụ trách: TV3 - Ngọc Thắng

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_SQL_PATH="${SCRIPT_DIR}/../lab-environment/db/init.sql"

echo "=========================================================="
echo " [QUY TRÌNH RESET DỮ LIỆU LAB] Bắt đầu hoàn nguyên CSDL..."
echo "=========================================================="

if [ -z "$(docker ps --filter "name=websec_mysql_db" --filter "status=running" --format "{{.Names}}")" ]; then
    echo "LỖI: Container 'websec_mysql_db' hiện không chạy!" >&2
    exit 1
fi

echo "[1/3] Đang nạp tệp cấu trúc và dữ liệu hạt giống (UTF-8): ${INIT_SQL_PATH}"
docker cp "${INIT_SQL_PATH}" websec_mysql_db:/tmp/init.sql
docker exec websec_mysql_db sh -c "mysql -u db_user -pP@ssword123 --default-character-set=utf8mb4 ecommerce_db < /tmp/init.sql"

echo "[2/3] Kiểm tra số lượng bản ghi sau khi hoàn nguyên:"
docker exec websec_mysql_db mysql -u db_user -pP@ssword123 --default-character-set=utf8mb4 ecommerce_db -e "SELECT 'users' AS table_name, count(*) AS row_count FROM users UNION ALL SELECT 'products', count(*) FROM products UNION ALL SELECT 'comments', count(*) FROM comments;"

echo "[3/3] Hoàn tất reset dữ liệu chuẩn UTF-8! Môi trường lab đã sẵn sàng."
echo "=========================================================="
