package com.anst.sd.api.security.app.impl;

import com.anst.sd.api.security.app.api.AuthErrorMessages;
import com.anst.sd.api.security.app.api.JwtResponse;
import com.anst.sd.api.security.domain.ERole;
import com.anst.sd.api.security.domain.JwtAuth;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.redisson.api.RMapCache;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static java.util.Optional.ofNullable;

@Log4j2
@Component
public class JwtService {
    public static final String USER_ID_CLAIM = "userId";
    public static final String DEVICE_ID_CLAIM = "deviceId";
    public static final String ROLE_ID_CLAIM = "role";
    public static final String TELEGRAM_ID_CLAIM = "telegramId";
    private final String jwtAccessSecret;
    private final String jwtRefreshSecret;
    private final String jwtStorageName;
    private final Duration accessTokenExpiration;
    private final Duration refreshTokenExpiration;
    private final RedissonClient redissonClient;
    private final Boolean blockRefreshValidAccessToken;

    public JwtService(
            @Value("${security.jwt.access.secret}") String jwtAccessSecret,
            @Value("${security.jwt.refresh.secret}") String jwtRefreshSecret,
            @Value("${security.jwt.storage}") String jwtStorageName,
            @Value("${security.jwt.access.expiration}") Duration accessTokenExpiration,
            @Value("${security.jwt.refresh.expiration}") Duration refreshTokenExpiration,
            RedissonClient redissonClient,
            @Value("${security.jwt.block-valid-access}") Boolean blockRefreshValidAccessToken
    ) {
        this.jwtAccessSecret = jwtAccessSecret;
        this.jwtRefreshSecret = jwtRefreshSecret;
        this.jwtStorageName = jwtStorageName;
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.redissonClient = redissonClient;
        this.blockRefreshValidAccessToken = blockRefreshValidAccessToken;
    }

    public JwtAuth getJwtAuth() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuth) {
            return ((JwtAuth) authentication);
        } else {
            return JwtAuth.builder().build();
        }
    }

    public boolean validateAccessTokenLifetime(Long deviceId) {
        if (blockRefreshValidAccessToken) {
            RMapCache<Long, String> map = redissonClient.getMapCache(jwtStorageName);
            String curAccessToken = map.get(deviceId);
            if (curAccessToken != null && validateAccessToken(map.get(deviceId))) {
                map.remove(deviceId);
                return false;
            }
        }
        return true;
    }

    public JwtResponse generateAccessRefreshTokens(String username, Long userId, Long deviceId, ERole role) {
        RMapCache<Long, String> map = redissonClient.getMapCache(jwtStorageName);
        String newAccessToken = generateAccessToken(username, userId, deviceId, role);
        map.put(deviceId,
                newAccessToken,
                accessTokenExpiration.toMinutes(),
                TimeUnit.MINUTES);

        return new JwtResponse(
                newAccessToken,
                generateRefreshToken(username, userId, deviceId, role));
    }

    public String generateAccessToken(String username, Long userId, Long deviceId, ERole role) {
        final Instant accessExpirationInstant =
                Instant.now().plus(accessTokenExpiration);
        final Date accessExpiration = Date.from(accessExpirationInstant);
        return Jwts.builder()
                .setExpiration(accessExpiration)
                .signWith(SignatureAlgorithm.HS512, jwtAccessSecret)
                .setSubject(username)
                .claim(USER_ID_CLAIM, userId.toString())
                .claim(DEVICE_ID_CLAIM, deviceId.toString())
                .claim(ROLE_ID_CLAIM, role)
                .compact();
    }

    public String generateTelegramIdAccessToken(String telegramId) {
        final Instant accessExpirationInstant =
            Instant.now().plus(accessTokenExpiration);
        final Date accessExpiration = Date.from(accessExpirationInstant);
        return Jwts.builder()
            .setExpiration(accessExpiration)
            .signWith(SignatureAlgorithm.HS512, jwtAccessSecret)
            .setSubject(telegramId)
            .claim(TELEGRAM_ID_CLAIM, telegramId)
            .compact();
    }

    public String generateRefreshToken(String username, Long userId, Long deviceId, ERole role) {
        final Instant refreshExpirationInstant = Instant.now().plus(refreshTokenExpiration);
        final Date refreshExpiration = Date.from(refreshExpirationInstant);
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(refreshExpiration)
                .claim(USER_ID_CLAIM, userId.toString())
                .claim(DEVICE_ID_CLAIM, deviceId.toString())
                .claim(ROLE_ID_CLAIM, role)
                .signWith(SignatureAlgorithm.HS512, jwtRefreshSecret)
                .compact();
    }

    public boolean validateAccessToken(@NonNull String token) {
        return validateToken(token, jwtAccessSecret);
    }

    public boolean validateRefreshToken(@NonNull String token) {
        return validateToken(token, jwtRefreshSecret);
    }

    private boolean validateToken(@NonNull String token, @NonNull String secret) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException expEx) {
            log.warn(AuthErrorMessages.TOKEN_EXPIRED, expEx);
        } catch (UnsupportedJwtException unsEx) {
            log.error(AuthErrorMessages.UNSUPPORTED_JWT, unsEx);
        } catch (MalformedJwtException mjEx) {
            log.error(AuthErrorMessages.MALFORMED_JWT, mjEx);
        } catch (SignatureException sEx) {
            log.error(AuthErrorMessages.INVALID_SIGNATURE, sEx);
        } catch (Exception e) {
            log.error(AuthErrorMessages.INVALID_TOKEN, e);
        }
        return false;
    }

    public ClaimsHolder getAccessClaims(@NonNull String token) {
        return new ClaimsHolder(getClaims(token, jwtAccessSecret));
    }

    public ClaimsHolder getRefreshClaims(@NonNull String token) {
        return new ClaimsHolder(getClaims(token, jwtRefreshSecret));
    }

    private Claims getClaims(@NonNull String token, @NonNull String secret) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    @RequiredArgsConstructor
    public static class ClaimsHolder {
        private final Claims claims;

        public String getUserId() {
            return claims.get(USER_ID_CLAIM, String.class);
        }

        public String getTelegramId() {
            return claims.get(TELEGRAM_ID_CLAIM, String.class);
        }

        public String getDeviceId() {
            return claims.get(DEVICE_ID_CLAIM, String.class);
        }

        public ERole getRole() {
            return ofNullable(claims.get(ROLE_ID_CLAIM, String.class))
                    .map(ERole::valueOf).orElse(null);
        }

        public String getUsername() {
            return claims.getSubject();
        }
    }
}