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
import org.springframework.web.ErrorResponse;
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
            User user = appController.resolveSessionUser(session);
            model.addAttribute("user", user);
        }
        model.addAttribute("appMode", "SECURED APP :8081");
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public String handleNotFound(NoResourceFoundException ex,
                                 HttpSession session,
                                 HttpServletRequest request,
                                 HttpServletResponse response,
                                 Model model) {
        response.setStatus(HttpStatus.NOT_FOUND.value());
        User user = appController.resolveSessionUser(session);
        model.addAttribute("user", user);
        model.addAttribute("status", 404);
        model.addAttribute("errorTitle", "Không tìm thấy trang yêu cầu (404)");
        model.addAttribute("errorMessage", "Trang bạn yêu cầu không tồn tại. Vui lòng kiểm tra lại đường dẫn hoặc sử dụng thanh điều hướng để quay về Trang chủ.");
        log.warn("[CORE-07][SECURED][404_NOT_FOUND] Truy cap duong dan khong ton tai: URI='{}'", request.getRequestURI());
        return "error";
    }

    @ExceptionHandler(Exception.class)
    public String handleGeneralException(Exception ex,
                                         HttpSession session,
                                         HttpServletRequest request,
                                         HttpServletResponse response,
                                         Model model) {
        if (ex instanceof ErrorResponse error && error.getStatusCode().is4xxClientError()) {
            int status = error.getStatusCode().value();
            error.getHeaders().forEach((name, values) -> values.forEach(value -> response.addHeader(name, value)));
            response.setStatus(status);
            model.addAttribute("status", status);
            model.addAttribute("errorTitle", "Yêu cầu không hợp lệ (" + status + ")");
            model.addAttribute("errorMessage", "Vui lòng kiểm tra lại yêu cầu.");
            return "error";
        }
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        User user = appController.resolveSessionUser(session);
        model.addAttribute("user", user);
        model.addAttribute("status", 500);
        model.addAttribute("errorTitle", "Dịch vụ tạm thời chưa sẵn sàng (500)");
        // BẢO MẬT: Tuyệt đối không lộ chi tiết SQL, tên bảng, Stack Trace hay thông tin nội bộ ra giao diện
        model.addAttribute("errorMessage", AppController.GENERIC_SERVICE_ERROR_MSG);
        log.error("[CORE-07][SECURED][EXCEPTION] Da chan ro ri loi noi bo tai URI='{}' - Chi tiet Server Log: {}",
                request.getRequestURI(), ex.getMessage());
        return "error";
    }
}
