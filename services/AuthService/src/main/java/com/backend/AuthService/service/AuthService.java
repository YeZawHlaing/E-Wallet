package com.backend.AuthService.service;

import com.backend.AuthService.dto.request.LoginRequest;
import com.backend.AuthService.dto.request.RegisterRequest;
import com.backend.AuthService.entity.User;
import com.backend.AuthService.repository.UserRepository;
import com.backend.AuthService.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, Object> redisTemplate;

    public String register(RegisterRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("ROLE_CUSTOMER")
                .build();

        userRepository.save(user);

        return "User registered successfully";
    }

    public Map<String, String> login(LoginRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(
                request.getPassword(),
                user.getPassword())) {

            throw new RuntimeException("Invalid credentials");
        }

        String accessToken =
                jwtUtil.generateAccessToken(user.getId(),user.getEmail(), user.getRole());

        String refreshToken =
                UUID.randomUUID().toString();

        redisTemplate.opsForValue().set(
                refreshToken,
                user.getEmail(),
                7,
                TimeUnit.DAYS
        );

        return Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken
        );
    }

    public String refresh(String refreshToken) {

        String email = (String)
                redisTemplate.opsForValue().get(refreshToken);

        if (email == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new RuntimeException("User not found"));

        return jwtUtil.generateAccessToken(
                user.getId(),
                user.getEmail(),
                user.getRole()
        );
    }
}