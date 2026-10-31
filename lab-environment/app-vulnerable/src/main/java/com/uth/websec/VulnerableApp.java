package com.uth.websec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VulnerableApp {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
        System.out.println("🚀 [VULNERABLE JAVA APP] Đang chạy tại cổng http://localhost:8080");
    }
}
