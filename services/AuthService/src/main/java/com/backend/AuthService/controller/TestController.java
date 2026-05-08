package com.backend.AuthService.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/customer/profile")
    public String profile() {

        return "Protected customer profile";
    }
}
