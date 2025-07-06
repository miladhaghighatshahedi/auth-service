package com.mhs.authService.token.model;

import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.UserService;
import com.mhs.authService.token.model.factory.RefreshTokenFactory;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.time.Instant;

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
