package com.backend.AuthService.controller;

import com.backend.AuthService.dto.request.LoginRequest;
import com.backend.AuthService.dto.request.RegisterRequest;
import com.backend.AuthService.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;


import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public String register(
            @RequestBody RegisterRequest request) {

        return authService.register(request);
    }

    @PostMapping("/login")
    public Map<String, String> login(
            @RequestBody LoginRequest request) {

        return authService.login(request);
    }

    @PostMapping("/refresh")
    public String refresh(
            @RequestParam String refreshToken) {

        return authService.refresh(refreshToken);
    }
}
