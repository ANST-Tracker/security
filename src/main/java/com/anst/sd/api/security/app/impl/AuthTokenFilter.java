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
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION = HttpHeaders.AUTHORIZATION;
    private static final String AUTHORIZATION_TELEGRAM = HttpHeaders.AUTHORIZATION + "-Telegram";
    private final RedissonClient redissonClient;
    private final JwtService jwtService;
    @Value("${security.jwt.storage}")
    private String jwtStorageName;
    @Value("${settings.dev-mode}")
    private boolean devMode;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (!devMode && request.getHeader(HttpHeaders.USER_AGENT) == null) {
            throw new AuthException("No user agent provided");
        }

        String basicAuthToken = parseJwt(request, AUTHORIZATION);
        String telegramAuthToken = parseJwt(request, AUTHORIZATION_TELEGRAM);
        if (isResolvableByTwoAuth(request)) {
            resolveDoubleAuthentication(request, basicAuthToken, telegramAuthToken);
        } else if (StringUtils.hasText(basicAuthToken) && !isResolvableByTelegramAuth(request)) {
            resolveBasicAuthentication(request, basicAuthToken);
        } else if (StringUtils.hasText(telegramAuthToken) && isResolvableByTelegramAuth(request)) {
            resolveTelegramAuthentication(request, telegramAuthToken);
        }
        filterChain.doFilter(request, response);
    }

    // ===================================================================================================================
    // = Implementation
    // ===================================================================================================================

    private void resolveTelegramAuthentication(HttpServletRequest request, String token) {
        validateTelegramClaims(token);
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        setSecurityContext(request, null, claims);
    }

    private void resolveBasicAuthentication(HttpServletRequest request, String token) {
        validateBasicClaims(token);
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        setSecurityContext(request, claims, null);
    }

    private void resolveDoubleAuthentication(HttpServletRequest request, String basicToken, String telegramToken) {
        validateBasicClaims(basicToken);
        validateTelegramClaims(telegramToken);
        JwtService.ClaimsHolder basicClaims = getTokenClaims(basicToken);
        JwtService.ClaimsHolder telegramClaims = getTokenClaims(telegramToken);
        setSecurityContext(request, basicClaims, telegramClaims);
    }

    private void validateBasicClaims(String token) {
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        RMapCache<UUID, String> map = redissonClient.getMapCache(jwtStorageName);
        if (claims == null || !token.equals(map.get(claims.getDeviceId()))) {
            throw new AuthException("Access Token doesn't refer to this user");
        }
    }

    private void validateTelegramClaims(String token) {
        JwtService.ClaimsHolder claims = getTokenClaims(token);
        if (claims == null || claims.getTelegramId() == null) {
            throw new AuthException("Access Token doesn't have telegramId");
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

    private void setSecurityContext(HttpServletRequest request, JwtService.ClaimsHolder basicClaims,
        JwtService.ClaimsHolder telegramClaims) {
        final JwtAuth authInfo = new JwtAuth();
        authInfo.setAuthenticated(true);
        if (basicClaims != null) {
            authInfo.setUsername(basicClaims.getUsername());
            authInfo.setUserId(basicClaims.getUserId());
            authInfo.setDeviceId(basicClaims.getDeviceId());
            authInfo.setRole(basicClaims.getRole());
        }
        if (telegramClaims != null) {
            authInfo.setTelegramId(telegramClaims.getTelegramId());
        }
        authInfo.setRemoteAddress(request.getRemoteAddr());
        authInfo.setUserAgent(request.getHeader(HttpHeaders.USER_AGENT));
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