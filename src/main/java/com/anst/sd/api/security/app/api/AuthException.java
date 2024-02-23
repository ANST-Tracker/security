package com.anst.sd.api.security.app.api;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.time.Instant;

@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthException extends RuntimeException {
    Long timestamp;

    public AuthException(String message) {
        super(message);
        this.timestamp = Instant.now().toEpochMilli();
    }
}
