package com.sooum.scg.jwt.filter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;


import java.nio.charset.StandardCharsets;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class TokenProvider {

    private final JwtProperties jwtProperties;

    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String BEARER = "Bearer ";
    private static final String ID_CLAIM = "id";

    public Optional<Long> getId(String token) {
        return Optional.ofNullable(getClaims(token).get(ID_CLAIM, Long.class));
    }

    public Optional<String> getToken(ServerHttpRequest request) {
        return Optional.ofNullable(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(token -> token.startsWith(BEARER))
                .map(token -> token.replace(BEARER, ""));
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(jwtProperties.getKey().getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isRefreshToken(String token) {
        return getClaims(token)
                .getSubject()
                .equals(REFRESH_TOKEN_SUBJECT);
    }
}
