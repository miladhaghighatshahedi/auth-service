package com.mhs.authService.token.model;

import java.time.Instant;

public interface RefreshTokenService {

    void saveRefreshToken( String username,
                           String hashedRefreshToken,
                           String deviceId,
                           String userAgent,
                           String ipAddress,
                           Instant refreshTokenIssuedDate,
                           Instant refreshTokenExpiryDate);

    void revokeToken(String hashedRefreshToken);

    boolean isTokenValid(String hashedRefreshToken, String deviceId, String userAgent, String ipAddress);

}
