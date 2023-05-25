package com.madeeasy.security.error.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException exc) throws IOException {
//        response.addHeader("access_denied_reason", "not_authorized");
        response.sendRedirect("/access-denied");// first priority
//        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");//second priority
    }
}

