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
package com.mhs.authService.token.model;

import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.UserService;
import com.mhs.authService.token.model.factory.RefreshTokenFactory;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.time.Instant;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@Service
@AllArgsConstructor
class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenFactory refreshTokenFactory;
    private final UserService userService;

    @Override
    @Transactional
    public void saveRefreshToken( String username,
                                  String hashedRefreshToken,
                                  String deviceId,
                                  String userAgent,
                                  String ipAddress,
                                  Instant refreshTokenIssuedDate,
                                  Instant refreshTokenExpiryDate) {

        User returnedUser = userService.findByUsername(username);
        refreshTokenRepository.deleteByUserAndDeviceId(returnedUser, deviceId);

        RefreshToken refreshToken = refreshTokenFactory.create( returnedUser,
                                                                hashedRefreshToken,
                                                                deviceId,
                                                                userAgent,
                                                                ipAddress,
                                                                refreshTokenIssuedDate,
                                                                refreshTokenExpiryDate,
                                                                false);

        refreshTokenRepository.save(refreshToken);
    }

    @Override
    @Transactional
    public void revokeToken(String hashedRefreshToken) {
        refreshTokenRepository.findByHashedToken(hashedRefreshToken).ifPresent(refreshTokenRepository::delete);
    }

    @Override
   public boolean isTokenValid(String hashedRefreshToken, String deviceId, String userAgent, String ipAddress) {
        return refreshTokenRepository.findByHashedToken(hashedRefreshToken)
                    .filter(refreshtoken -> !refreshtoken.isRevoked())
                    .filter(refreshtoken -> !refreshtoken.getExpiryDate().isBefore(Instant.now()))
                    .filter(refreshtoken -> refreshtoken.getDeviceId().equals(deviceId))
                    .filter(refreshtoken -> refreshtoken.getUserAgent().equals(userAgent))
                    .filter(refreshtoken -> refreshtoken.getIpAddress().equals(ipAddress))
                    .isPresent();
   }

}
