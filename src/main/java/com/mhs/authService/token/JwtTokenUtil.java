package com.mhs.authService.token;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Component
@Data
@RequiredArgsConstructor
public class JwtTokenUtil {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final TokenProperties tokenProperties;

    public String generateAccessToken(Authentication authentication, String deviceId, String userAgent, String ipAddress) {
        Instant now = Instant.now();
        Instant accessTokenExpiry = now.plus(tokenProperties.getAccessTokenExpiryHours(), ChronoUnit.HOURS);

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(tokenProperties.getAccessTokenIssuer())
                .issuedAt(now)
                .expiresAt(accessTokenExpiry)
                .subject(authentication.getName())
                .claim("scope", scope)
                .claim("type", tokenProperties.getAccessTokenClaimType())
                .claim("X-Device-Id", deviceId)
                .claim("User-Agent", userAgent)
                .claim("Ip-Address", ipAddress)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateRefreshToken(Authentication authentication, String deviceId, String userAgent, String ipAddress) {

        Instant now = Instant.now();
        Instant refreshTokenExpiry = now.plus(tokenProperties.getRefreshTokenExpiryHours(),ChronoUnit.HOURS);

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(tokenProperties.getRefreshTokenIssuer())
                .issuedAt(now)
                .expiresAt(refreshTokenExpiry)
                .subject(authentication.getName())
                .claim("scope", scope)
                .claim("type", tokenProperties.getRefreshTokenClaimType())
                .claim("X-Device-Id", deviceId)
                .claim("User-Agent", userAgent)
                .claim("Ip-Address", ipAddress)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

}

