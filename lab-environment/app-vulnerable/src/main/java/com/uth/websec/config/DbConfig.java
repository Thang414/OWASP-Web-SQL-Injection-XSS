package com.uth.websec.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

@Configuration
public class DbConfig {

    @Value("${db.host:db}")
    private String host;

    @Value("${db.port:3306}")
    private String port;

    @Value("${db.name:ecommerce_db}")
    private String dbName;

    @Value("${db.user:db_user}")
    private String user;

    @Value("${db.pass:P@ssword123}")
    private String password;

    @Value("${db.url:}")
    private String customUrl;

    @PostConstruct
    public void initLocalFallbackIfNeeded() {
        if (customUrl == null || customUrl.isBlank()) {
            try {
                InetAddress.getByName(host);
            } catch (Exception e) {
                customUrl = "jdbc:h2:mem:vuln_lab_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
                user = "sa";
                password = "";
                System.out.println("[LAB LOCAL MODE - VULNERABLE]: Không tìm thấy host '" + host + "', tự động khởi tạo CSDL giả lập H2 (MySQL Mode) từ init.sql");
                seedH2DatabaseFromInitSql();
            }
        } else if (customUrl.startsWith("jdbc:h2:")) {
            seedH2DatabaseFromInitSql();
        }
    }

    private void seedH2DatabaseFromInitSql() {
        try {
            Path initSqlPath = Path.of("../db/init.sql");
            if (!Files.exists(initSqlPath)) {
                initSqlPath = Path.of("lab-environment/db/init.sql");
            }
            if (!Files.exists(initSqlPath)) {
                return;
            }
            String rawSql = Files.readString(initSqlPath, StandardCharsets.UTF_8);
            StringBuilder cleanedSql = new StringBuilder();
            for (String line : rawSql.split("\\R")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("--")) {
                    continue;
                }
                String upper = trimmed.toUpperCase();
                if (upper.startsWith("CREATE DATABASE") || upper.startsWith("USE ")) {
                    continue;
                }
                cleanedSql.append(line).append("\n");
            }
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement()) {
                for (String statement : cleanedSql.toString().split(";")) {
                    String sql = statement.trim();
                    if (!sql.isEmpty()) {
                        stmt.execute(sql);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[LAB LOCAL MODE] Lỗi nạp init.sql: " + e.getMessage());
        }
    }

    public Connection getConnection() throws SQLException {
        // Cấu hình JDBC cho phép allowMultiQueries=true (dễ khai thác SQLi với dấu comment và nhiều lệnh)
        String url = (customUrl != null && !customUrl.isBlank())
                ? customUrl
                : "jdbc:mysql://" + host + ":" + port + "/" + dbName +
                  "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&characterEncoding=UTF-8&allowMultiQueries=true";
        return DriverManager.getConnection(url, user, password);
    }
}
