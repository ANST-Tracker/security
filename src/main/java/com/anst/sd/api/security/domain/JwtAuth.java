package com.anst.sd.api.security.domain;

import lombok.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtAuth implements Authentication {
    private boolean authenticated;
    private String username;
    private Long userId;
    private Long deviceId;
    private ERole role;
    private String telegramId;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(role);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return username;
    }
}
