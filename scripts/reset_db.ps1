# Quy trình reset dữ liệu cơ sở dữ liệu mẫu cho lab (INFRA-06)
# Phụ trách: TV3 - Ngọc Thắng

$ErrorActionPreference = "Stop"

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

Write-Host "[1/3] Đang nạp tệp cấu trúc và dữ liệu hạt giống: $initSqlPath" -ForegroundColor Yellow
Get-Content -Path $initSqlPath -Raw -Encoding UTF8 | docker exec -i websec_mysql_db mysql -u db_user -pP@ssword123 ecommerce_db

Write-Host "[2/3] Kiểm tra số lượng bản ghi sau khi hoàn nguyên:" -ForegroundColor Yellow
$verifySql = "SELECT 'users' AS table_name, count(*) AS row_count FROM users UNION ALL SELECT 'products', count(*) FROM products UNION ALL SELECT 'comments', count(*) FROM comments;"
docker exec websec_mysql_db mysql -u db_user -pP@ssword123 ecommerce_db -e $verifySql

Write-Host "[3/3] Hoàn tất reset dữ liệu! Môi trường lab đã sẵn sàng cho lượt thử nghiệm tiếp theo." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
