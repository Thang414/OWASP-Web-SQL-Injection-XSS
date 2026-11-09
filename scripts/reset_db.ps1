# Quy trình reset dữ liệu cơ sở dữ liệu mẫu cho lab (INFRA-06 / CORE-02 / CORE-03)
# Phụ trách: TV3 - Ngọc Thắng

$ErrorActionPreference = "Stop"

# Thiết lập bảng mã console UTF-8 để hiển thị đúng dấu tiếng Việt trên terminal Windows
chcp 65001 >$null 2>&1
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [QUY TRÌNH RESET DỮ LIỆU LAB] Bắt đầu hoàn nguyên CSDL..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Kiểm tra container CSDL
$containerRunning = docker ps --filter "name=websec_mysql_db" --filter "status=running" --format "{{.Names}}"
if (-not $containerRunning) {
    Write-Error "Container 'websec_mysql_db' hiện không chạy! Vui lòng khởi động môi trường qua 'docker compose up -d' trước."
}

$initSqlPath = Join-Path $PSScriptRoot "..\lab-environment\db\init.sql"
if (-not (Test-Path $initSqlPath)) {
    Write-Error "Không tìm thấy tệp khởi tạo dữ liệu tại: $initSqlPath"
}

Write-Host "[1/3] Đang nạp tệp cấu trúc và dữ liệu hạt giống (UTF-8): $initSqlPath" -ForegroundColor Yellow

# Sao chép tệp init.sql trực tiếp vào container để nạp với --default-character-set=utf8mb4
# Tránh hoàn toàn lỗi mã hóa ký tự tiếng Việt do PowerShell pipeline trên Windows gây ra
docker cp "$initSqlPath" websec_mysql_db:/tmp/init.sql
docker exec websec_mysql_db sh -c "mysql -u db_user -pP@ssword123 --default-character-set=utf8mb4 ecommerce_db < /tmp/init.sql"

Write-Host "[2/3] Kiểm tra số lượng bản ghi sau khi hoàn nguyên:" -ForegroundColor Yellow
$verifySql = "SELECT 'users' AS table_name, count(*) AS row_count FROM users UNION ALL SELECT 'products', count(*) FROM products UNION ALL SELECT 'comments', count(*) FROM comments;"
docker exec websec_mysql_db mysql -u db_user -pP@ssword123 --default-character-set=utf8mb4 ecommerce_db -e $verifySql

Write-Host "[3/3] Hoàn tất reset dữ liệu chuẩn UTF-8! Môi trường lab đã sẵn sàng." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
