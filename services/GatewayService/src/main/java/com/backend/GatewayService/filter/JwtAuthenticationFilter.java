package com.backend.GatewayService.filter;

import com.backend.GatewayService.security.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter
        implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(
            ServerWebExchange exchange,
            GatewayFilterChain chain) {


        String path =
                exchange.getRequest().getURI().getPath();

        // Public endpoints
        if (
                path.contains("/auth/login") ||
                        path.contains("/auth/register") ||
                        path.contains("/auth/refresh")
        ) {
            return chain.filter(exchange);
        }

        String authHeader =
                exchange.getRequest()
                        .getHeaders()
                        .getFirst(HttpHeaders.AUTHORIZATION);

        // Missing token
        if (
                authHeader == null ||
                        !authHeader.startsWith("Bearer ")
        ) {

            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete();
        }

        String token =
                authHeader.substring(7);

        // Invalid token
        if (!jwtUtil.validateToken(token)) {

            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete();
        }


        Claims claims = jwtUtil.extractClaims(token);

        String userId = claims.getSubject();

        String email = claims.get("email", String.class);

        String role = claims.get("role", String.class);


        // Forward user info to downstream services
        ServerHttpRequest request =
                exchange.getRequest()
                        .mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Email", email)
                        .header("X-User-Role", role)
                        .build();

        return chain.filter(
                exchange.mutate()
                        .request(request)
                        .build()
        );
    }

    @Override
    public int getOrder() {
        return -1;
    }
}