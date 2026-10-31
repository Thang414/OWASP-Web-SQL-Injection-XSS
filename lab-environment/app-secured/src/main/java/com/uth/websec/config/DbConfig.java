package com.uth.websec.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

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

    public Connection getConnection() throws SQLException {
        // Cấu hình JDBC an toàn: không bật allowMultiQueries
        String url = "jdbc:mysql://" + host + ":" + port + "/" + dbName +
                "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&characterEncoding=UTF-8";
        return DriverManager.getConnection(url, user, password);
    }
}
