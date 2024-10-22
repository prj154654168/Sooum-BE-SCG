package com.sooum.scg.config;

import com.sooum.scg.jwt.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class GateWayConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("permit-all", r -> r.path("/users/key",
                                "/users/sign-up",
                                "/users/login",
                                "/profiles/nickname/{nickname}/available",
                                "/settings/transfer")
                        .uri("http://localhost:9090"))
                .route("/test",r->r.path("/**")
                        .filters(f->f.filter(jwtAuthenticationFilter))
                        .uri("http://localhost:9090"))
                .build();
    }
}
