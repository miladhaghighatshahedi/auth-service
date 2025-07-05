package com.mhs.authService.token.model;

import java.time.Instant;

public interface RefreshTokenService {

    void saveRefreshToken( String username,
                           String token,
                           String deviceId,
                           String userAgent,
                           String ipAddress,
                           Instant refreshTokenIssuedDate,
                           Instant refreshTokenExpiryDate);

    void revokeToken(String refreshToken);

    boolean isTokenValid(String token, String deviceId, String userAgent, String ipAddress);

}
