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
                                  String hashedToken,
                                  String deviceId,
                                  String userAgent,
                                  String ipAddress,
                                  Instant refreshTokenIssuedDate,
                                  Instant refreshTokenExpiryDate) {

        User returnedUser = userService.findByUsername(username);
        refreshTokenRepository.deleteByUserAndDeviceId(returnedUser, deviceId);


        RefreshToken refreshToken = refreshTokenFactory.create( returnedUser,
                                                                hashedToken,
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
    public void revokeToken(String refreshToken) {
    }

    @Override
   public boolean isTokenValid(String token, String deviceId, String userAgent, String ipAddress) {
        return true;
   }

}
