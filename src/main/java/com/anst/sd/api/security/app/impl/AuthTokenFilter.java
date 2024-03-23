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
        if (isResolvableByTwoAuth(request)) {
            resolveDoubleAuthentication(basicAuthToken, telegramAuthToken);
        } else if (StringUtils.hasText(basicAuthToken) && !isResolvableByTelegramAuth(request)) {
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
        validateTelegramClaims(token);
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        setSecurityContext(null, claims);
    }

    private void resolveBasicAuthentication(String token) {
        validateBasicClaims(token);
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        setSecurityContext(claims, null);
    }

    private void validateBasicClaims(String token) {
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        RMapCache<Long, String> map = redissonClient.getMapCache(jwtStorageName);
        if (claims == null || !token.equals(map.get(Long.parseLong(claims.getDeviceId())))) {
            throw new AuthException("Access Token doesn't refer to this user");
        }
    }

    private void validateTelegramClaims(String token) {
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        if (claims == null || claims.getTelegramId() == null) {
            throw new AuthException("Access Token doesn't have telegramId");
        }
    }

    private void resolveDoubleAuthentication(String basicToken, String telegramToken) {
        validateBasicClaims(basicToken);
        JwtService.ClaimsHolder basicClaims = getTokenClaims(basicToken);
        JwtService.ClaimsHolder telegramClaims = getTokenClaims(telegramToken);
        setSecurityContext(basicClaims, telegramClaims);
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

    private void setSecurityContext(JwtService.ClaimsHolder basicClaims, JwtService.ClaimsHolder telegramClaims) {
        final JwtAuth authInfo = new JwtAuth();
        authInfo.setAuthenticated(true);
        if (basicClaims != null) {
            authInfo.setUsername(basicClaims.getUsername());
            authInfo.setUserId(Long.parseLong(basicClaims.getUserId()));
            authInfo.setDeviceId(Long.parseLong(basicClaims.getDeviceId()));
            authInfo.setRole(basicClaims.getRole());
        }
        if (telegramClaims != null) {
            authInfo.setTelegramId(telegramClaims.getTelegramId());
        }
        SecurityContextHolder.getContext().setAuthentication(authInfo);
    }

    private boolean isResolvableByTelegramAuth(HttpServletRequest request) {
        return WebSecurityConfig.TELEGRAM_AUTH_URLS.stream()
            .anyMatch(url -> request.getRequestURI().contains(url));
    }

    private boolean isResolvableByTwoAuth(HttpServletRequest request) {
        return WebSecurityConfig.TWO_AUTH_URLS.stream()
            .anyMatch(url -> request.getRequestURI().contains(url));
    }
}
