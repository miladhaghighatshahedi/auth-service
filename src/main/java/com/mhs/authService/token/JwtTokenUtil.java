/*
 * Copyright 2025-2026 the original author.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mhs.authService.token;

import com.mhs.authService.exception.error.InvalidTokenException;
import com.mhs.authService.token.dto.RefreshTokenRequest;
import com.mhs.authService.token.model.RefreshTokenService;
import com.mhs.authService.util.hash.HashService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@Component
@Data
@RequiredArgsConstructor
public class JwtTokenUtil {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final TokenProperties tokenProperties;
    private final HashService hashService;
    private final RefreshTokenService refreshTokenService;

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
        validateRefreshTokenFingerPrintsExpiryAgainstDB(hashService.hashToken(rawRefreshToken),deviceId,userAgent,ipAddress);
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

    public void validateRefreshTokenFingerPrintsExpiryAgainstDB(String hashedRefreshToken,String deviceId,String userAgent,String ipAddress){
        boolean validRefreshTokenInDB = refreshTokenService.isTokenValid(hashedRefreshToken, deviceId, userAgent, ipAddress);
        if (!validRefreshTokenInDB) {
            throw new InvalidTokenException("error: Refresh token revoked or not valid for this device!");
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

    public Authentication buildAuthenticationFromJwt(Jwt decodedJwt){

        String username = decodedJwt.getSubject();
        String scope = decodedJwt.getClaimAsString("scope");

        List<GrantedAuthority> authorities = Arrays.stream(scope.split(" "))
                .filter(s -> !s.isBlank())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UserDetails principal = new User(username, "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, null, authorities);

    }

}

