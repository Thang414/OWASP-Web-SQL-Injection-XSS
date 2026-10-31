package com.uth.websec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecuredApp {

    public static void main(String[] args) {
        SpringApplication.run(SecuredApp.class, args);
        System.out.println("🛡️ [SECURED JAVA APP] Đang chạy tại cổng http://localhost:8081");
    }
}
