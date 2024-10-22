package com.sooum.scg.jwt.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter implements GatewayFilter {

    private final TokenProvider tokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token;
        try {
            token = tokenProvider.getToken(request).get();
        } catch (NoSuchElementException e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            String message = "토큰이 없습니다";
            byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
            DataBuffer wrap = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(wrap));
        }
        if (tokenProvider.isRefreshToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            String message = "리프레시 토큰입니다";
            byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
            DataBuffer wrap = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(wrap));

        }
        Long userPk = tokenProvider.getId(token).orElseThrow(NoSuchElementException::new);
        exchange.getRequest().mutate().header(HttpHeaders.AUTHORIZATION, userPk.toString()).build();
        return chain.filter(exchange);
    }
}
