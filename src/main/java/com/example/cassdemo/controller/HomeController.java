package com.example.cassdemo.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal UserDetails user, Model model) {
        if (user != null) {
            model.addAttribute("username", user.getUsername());
            model.addAttribute("roles", user.getAuthorities());
        }
        return "home";
    }

    @GetMapping("/public/info")
    public String publicInfo() {
        return "public-info";
    }

    @GetMapping("/secure/dashboard")
    public String dashboard(@AuthenticationPrincipal UserDetails user, Model model) {
        model.addAttribute("username", user.getUsername());
        model.addAttribute("roles", user.getAuthorities());
        return "dashboard";
    }
}
