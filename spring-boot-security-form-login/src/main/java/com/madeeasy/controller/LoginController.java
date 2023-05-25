package com.madeeasy.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String viewLoginPage() {
        return "login";
    }
    @GetMapping("/access-denied")
    public String accessDenied() {
        return "accessdenied";
    }

    @GetMapping("/invalid-session")
    public String invalidSession() {
        return "invalidSession";
    }
}
