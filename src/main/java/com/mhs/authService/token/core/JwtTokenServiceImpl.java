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
package com.mhs.authService.token.core;

import com.mhs.authService.infrastructure.hash.TokenHashService;
import com.mhs.authService.token.dto.RefreshTokenCarrier;
import com.mhs.authService.token.refresh.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("jwtTokenService")
@RequiredArgsConstructor
class JwtTokenServiceImpl implements JwtTokenService{

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final JwtTokenProperties jwtTokenProperties;
    private final RefreshTokenService refreshTokenService;
    private final TokenHashService SHA256TokenHash;

    public String generateAccessToken(Authentication authentication, String deviceId, String userAgent, String ipAddress) {
        Instant now = Instant.now();
        Instant accessTokenExpiry = now.plus(jwtTokenProperties.getAccessTokenExpiryHours(), ChronoUnit.HOURS);

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtTokenProperties.getAccessTokenIssuer())
                .issuedAt(now)
                .expiresAt(accessTokenExpiry)
                .subject(authentication.getName())
                .claim("scope", scope)
                .claim("type", jwtTokenProperties.getAccessTokenClaimType())
                .claim("X-Device-Id", deviceId)
                .claim("User-Agent", userAgent)
                .claim("Ip-Address", ipAddress)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateRefreshToken(Authentication authentication, String deviceId, String userAgent, String ipAddress) {

        Instant now = Instant.now();
        Instant refreshTokenExpiry = now.plus(jwtTokenProperties.getRefreshTokenExpiryHours(),ChronoUnit.HOURS);

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtTokenProperties.getRefreshTokenIssuer())
                .issuedAt(now)
                .expiresAt(refreshTokenExpiry)
                .subject(authentication.getName())
                .claim("scope", scope)
                .claim("type", jwtTokenProperties.getRefreshTokenClaimType())
                .claim("X-Device-Id", deviceId)
                .claim("User-Agent", userAgent)
                .claim("Ip-Address", ipAddress)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public Jwt validateRefreshToken(RefreshTokenCarrier refreshTokenRequest, String deviceId, String userAgent, String ipAddress){

        String rawRefreshToken = refreshTokenRequest.refreshToken();
        Jwt decodedJwt = jwtDecoder.decode(rawRefreshToken);

        validateRefreshTokenType(decodedJwt);
        validateRefreshTokenExpiry(decodedJwt);
        validateRefreshTokenFingerPrintsExpiryAgainstDB(SHA256TokenHash.hashToken(rawRefreshToken),deviceId,userAgent,ipAddress);
        validateTokenFingerPrints(decodedJwt,deviceId,userAgent,ipAddress);

        return decodedJwt;
    }

    public Jwt validateAccessToken(String rawAccessToken){

        Jwt decodedJwt = jwtDecoder.decode(rawAccessToken);

        validateAccessTokenType(decodedJwt);
        validateAccessTokenExpiry(decodedJwt);
        validateAccessTokenIssuer(decodedJwt);

        return decodedJwt;
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

    private void validateRefreshTokenType(Jwt decodedJwt){
        if (!jwtTokenProperties.getRefreshTokenClaimType().equals(decodedJwt.getClaimAsString("type"))) {
            throw new BadCredentialsException("error: Invalid Token Type! (expected refresh token)");
        }
    }

    private void validateAccessTokenType(Jwt decodedJwt){
        if (!jwtTokenProperties.getAccessTokenClaimType().equals(decodedJwt.getClaimAsString("type"))) {
            throw new BadCredentialsException("error: Invalid Token Type! (expected access token)");
        }
    }

    private void validateRefreshTokenExpiry(Jwt decodedJwt){
        if (decodedJwt.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("error: Refresh token is expired or revoked!");
        }
    }

    private void validateAccessTokenExpiry(Jwt decodedJwt){
        if (decodedJwt.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("error: Access token is expired!");
        }
    }

    private void validateAccessTokenIssuer(Jwt decodedJwt){
        String issuer = decodedJwt.getIssuer().toString();
        if(!issuer.equals(jwtTokenProperties.getAccessTokenIssuer())){
            throw new BadCredentialsException("Issuer mismatch! (invalid access token)");
        }
    }

    private void validateRefreshTokenFingerPrintsExpiryAgainstDB(String hashedRefreshToken,String deviceId,String userAgent,String ipAddress){
        boolean validRefreshTokenInDB = refreshTokenService.isTokenValid(hashedRefreshToken, deviceId, userAgent, ipAddress);
        if (!validRefreshTokenInDB) {
            throw new BadCredentialsException("error: Refresh token revoked or not valid for this device!");
        }
    }

    private void validateTokenFingerPrints(Jwt decodedJwt,String deviceId,String userAgent,String ipAddress){

        String tokenDeviceId  = decodedJwt.getClaimAsString("X-Device-Id");
        String tokenUserAgent = decodedJwt.getClaimAsString("User-Agent");
        String tokenIpAddress = decodedJwt.getClaimAsString("Ip-Address");
        String issuer = decodedJwt.getIssuer().toString();

        if (!deviceId.equals(tokenDeviceId)) {
            throw new BadCredentialsException("Device mismatch – refresh token misuse suspected!");
        }

        if (!userAgent.equals(tokenUserAgent)) {
            throw new BadCredentialsException("UserAgent mismatch – refresh token misuse suspected!");
        }

        if (!ipAddress.equals(tokenIpAddress)) {
            throw new BadCredentialsException("IpAddress mismatch – refresh token misuse suspected!");
        }

        if(!issuer.equals(jwtTokenProperties.getRefreshTokenIssuer())){
            throw new BadCredentialsException("Issuer mismatch – refresh token misuse suspected!");
        }
    }

}

