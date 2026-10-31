package com.uth.websec.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;

        // 1. Chống Clickjacking
        res.setHeader("X-Frame-Options", "DENY");

        // 2. Chống MIME-sniffing
        res.setHeader("X-Content-Type-Options", "nosniff");

        // 3. Content Security Policy (CSP): Ngăn chặn inline script và domain lạ
        res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline';");

        chain.doFilter(request, response);
    }
}
