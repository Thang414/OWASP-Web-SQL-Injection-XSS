package com.uth.websec.controller;

import com.uth.websec.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@ControllerAdvice
public class GlobalControllerAdvice {

    private static final Logger log = LoggerFactory.getLogger(GlobalControllerAdvice.class);

    @Autowired
    private AppController appController;

    @ModelAttribute
    public void populateCommonAttributes(HttpSession session, HttpServletRequest request, Model model) {
        if (!model.containsAttribute("user")) {
            User user = appController.resolveSessionUser(session, request);
            model.addAttribute("user", user);
        }
        model.addAttribute("appMode", "VULNERABLE LAB :8080");
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public String handleNotFound(NoResourceFoundException ex,
                                 HttpSession session,
                                 HttpServletRequest request,
                                 HttpServletResponse response,
                                 Model model) {
        response.setStatus(HttpStatus.NOT_FOUND.value());
        User user = appController.resolveSessionUser(session, request);
        model.addAttribute("user", user);
        model.addAttribute("status", 404);
        model.addAttribute("errorTitle", "Không tìm thấy trang yêu cầu (404)");
        model.addAttribute("errorMessage", "Đường dẫn bạn truy cập không tồn tại hoặc đã bị di chuyển: " + request.getRequestURI());
        log.warn("[CORE-07][VULNERABLE][404_NOT_FOUND] Truy cap duong dan khong ton tai: URI='{}'", request.getRequestURI());
        return "error";
    }

    @ExceptionHandler(Exception.class)
    public String handleGeneralException(Exception ex,
                                         HttpSession session,
                                         HttpServletRequest request,
                                         HttpServletResponse response,
                                         Model model) {
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        User user = appController.resolveSessionUser(session, request);
        model.addAttribute("user", user);
        model.addAttribute("status", 500);
        model.addAttribute("errorTitle", "Lỗi hệ thống hoặc Dịch vụ chưa sẵn sàng (500)");
        // Bản Vulnerable giữ chi tiết ngoại lệ phục vụ Lab nghiên cứu
        model.addAttribute("errorMessage", "Chi tiết lỗi hệ thống (Vulnerable Lab): " + ex.getMessage());
        log.error("[CORE-07][VULNERABLE][EXCEPTION] Loi khong mong doi tai URI='{}': {}", request.getRequestURI(), ex.getMessage());
        return "error";
    }
}
