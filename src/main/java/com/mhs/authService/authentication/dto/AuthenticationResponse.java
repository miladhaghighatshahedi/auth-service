package com.mhs.authService.authentication.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import java.time.Instant;
import java.util.Set;

@Data
@AllArgsConstructor
public class AuthenticationResponse {

    private String  accessToken;
    private String  refreshToken;
    private Instant expiresAt;
    private String  username;
    private final Set<? extends GrantedAuthority> authorities;
    private String message;

}
