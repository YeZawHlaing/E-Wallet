package com.backend.AuthService.controller;

import com.backend.AuthService.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class OtpController {

    private final AuthService authService;

    @PostMapping("/send-otp")
    public String sendOtp(
            @RequestParam String email
    ) {

        return authService.sendOtp(email);
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(
            @RequestParam String email,
            @RequestParam String otp
    ) {

        return authService.verifyOtp(email, otp);
    }
}