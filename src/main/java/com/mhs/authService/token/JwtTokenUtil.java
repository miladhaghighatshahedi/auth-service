package com.mhs.authService.token;

import com.mhs.authService.exception.error.InvalidTokenException;
import com.mhs.authService.token.dto.RefreshTokenRequest;
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

    public Jwt validateRefreshToken(RefreshTokenRequest refreshTokenRequest, String deviceId, String userAgent, String ipAddress){

        String rawRefreshToken = refreshTokenRequest.refreshToken();
        Jwt decodedJwt = jwtDecoder.decode(rawRefreshToken);

        validateRefreshTokenType(decodedJwt);
        validateRefreshTokenExpiry(decodedJwt);
        validateTokenFingerPrints(decodedJwt,deviceId,userAgent,ipAddress);

        return decodedJwt;
    }

    public void validateRefreshTokenType(Jwt decodedJwt){
        if (!tokenProperties.getRefreshTokenClaimType().equals(decodedJwt.getClaimAsString("type"))) {
            throw new JwtException("error: Invalid Token Type!");
        }
    }

    public void validateRefreshTokenExpiry(Jwt decodedJwt){
        if (decodedJwt.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidTokenException("error: Refresh token is expired or revoked!");
        }
    }

    public void validateTokenFingerPrints(Jwt decodedJwt,String deviceId,String userAgent,String ipAddress){

        String tokenDeviceId  = decodedJwt.getClaimAsString("X-Device-Id");
        String tokenUserAgent = decodedJwt.getClaimAsString("User-Agent");
        String tokenIpAddress = decodedJwt.getClaimAsString("Ip-Address");
        String issuer = decodedJwt.getIssuer().toString();

        if (!deviceId.equals(tokenDeviceId)) {
            throw new InvalidTokenException("Device mismatch – refresh token misuse suspected!");
        }

        if (!userAgent.equals(tokenUserAgent)) {
            throw new InvalidTokenException("UserAgent mismatch – refresh token misuse suspected!");
        }

        if (!ipAddress.equals(tokenIpAddress)) {
            throw new InvalidTokenException("IpAddress mismatch – refresh token misuse suspected!");
        }

        if(!issuer.equals(tokenProperties.getRefreshTokenIssuer())){
            throw new InvalidTokenException("Issuer mismatch – refresh token misuse suspected!");
        }
    }

}

