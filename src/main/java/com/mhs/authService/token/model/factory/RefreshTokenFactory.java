package com.mhs.authService.token.model.factory;

import com.mhs.authService.iam.user.User;
import com.mhs.authService.token.model.RefreshToken;
import org.springframework.stereotype.Component;
import java.time.Instant;

@Component
public class RefreshTokenFactory {

	public RefreshToken create( User user,
	                          String hashedToken,
	                          String deviceId,
	                          String userAgent,
	                          String ipAddress,
	                          Instant refreshTokenIssuedDate,
	                          Instant refreshTokenExpiryDate,
	                          boolean revoked) {

		RefreshToken refreshToken = new RefreshToken();
		refreshToken.setUser(user);
		refreshToken.setHashedToken(hashedToken);
		refreshToken.setDeviceId(deviceId);
		refreshToken.setUserAgent(userAgent);
		refreshToken.setIpAddress(ipAddress);
		refreshToken.setExpiryDate(refreshTokenExpiryDate);
		refreshToken.setIssuedDate(refreshTokenIssuedDate);
		refreshToken.setRevoked(revoked);

		return refreshToken;
	}

}
