package com.anst.sd.api.security.app.impl;

import com.anst.sd.api.security.app.api.AuthException;
import com.anst.sd.api.security.domain.JwtAuth;
import com.anst.sd.api.security.fw.WebSecurityConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.http.HttpHeaders;
import org.redisson.api.RMapCache;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION = HttpHeaders.AUTHORIZATION;
    private static final String AUTHORIZATION_TELEGRAM = HttpHeaders.AUTHORIZATION + "-Telegram";
    private final RedissonClient redissonClient;
    private final JwtService jwtService;
    @Value("${security.jwt.storage}")
    private String jwtStorageName;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String basicAuthToken = parseJwt(request, AUTHORIZATION);
        String telegramAuthToken = parseJwt(request, AUTHORIZATION_TELEGRAM);
        if (StringUtils.hasText(basicAuthToken) && !isResolvableByTelegramAuth(request)) {
            resolveBasicAuthentication(basicAuthToken);
        } else if (StringUtils.hasText(telegramAuthToken) && isResolvableByTelegramAuth(request)) {
            resolveTelegramAuthentication(telegramAuthToken);
        }
        filterChain.doFilter(request, response);
    }

    // ===================================================================================================================
    // = Implementation
    // ===================================================================================================================

    private void resolveTelegramAuthentication(String token) {
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        if (claims != null && claims.getTelegramId() != null) {
            setSecurityContext(claims);
        } else {
            throw new AuthException("Access Token doesn't have telegramId");
        }
    }

    private void resolveBasicAuthentication(String token) {
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        if (claims != null) {
            RMapCache<Long, String> map = redissonClient.getMapCache(jwtStorageName);
            if (token.equals(map.get(Long.parseLong(claims.getDeviceId())))) {
                setSecurityContext(claims);
            } else {
                throw new AuthException("Access Token doesn't refer to this user");
            }
        }
    }

    private String parseJwt(HttpServletRequest request, String headerName) {
        String headerAuth = request.getHeader(headerName);
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }

    private JwtService.ClaimsHolder getTokenClaims(String token) {
        if (jwtService.validateAccessToken(token)) {
            return jwtService.getAccessClaims(token);
        }
        return null;
    }

    private void setSecurityContext(JwtService.ClaimsHolder claims) {
        final JwtAuth authInfo = JwtAuth.builder()
            .username(claims.getUsername())
            .userId(Long.parseLong(claims.getUserId()))
            .deviceId(Long.parseLong(claims.getDeviceId()))
            .role(claims.getRole())
            .authenticated(true)
            .build();
        SecurityContextHolder.getContext().setAuthentication(authInfo);
    }

    private boolean isResolvableByTelegramAuth(HttpServletRequest request) {
        return WebSecurityConfig.telegramAuthUrls.stream()
            .anyMatch(url -> request.getRequestURI().contains(url));
    }
}
