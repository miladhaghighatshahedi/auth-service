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
package com.mhs.authService.authentication.logout;

import com.mhs.authService.authentication.logout.dto.LogoutRequest;
import com.mhs.authService.authentication.logout.dto.LogoutResponse;
import com.mhs.authService.infrastructure.fingerprint.RequestFingerprint;
import com.mhs.authService.infrastructure.fingerprint.RequestFingerprintExtractor;
import com.mhs.authService.infrastructure.hash.TokenHashService;
import com.mhs.authService.token.core.JwtTokenService;
import com.mhs.authService.token.refresh.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("logoutService")
@RequiredArgsConstructor
class LogoutServiceImpl implements LogoutService{

	private final TokenHashService SHA256TokenHash;
	private final JwtTokenService jwtTokenService;
	private final RefreshTokenService refreshTokenService;
	private final RequestFingerprintExtractor authenticationRequestFingerprint;
	private final TransactionTemplate transactionTemplate;

	@Override
	public LogoutResponse logout(LogoutRequest logoutRequest, HttpServletRequest httpServletRequest) {

		RequestFingerprint fingerprint = authenticationRequestFingerprint.extractFrom(httpServletRequest);

		jwtTokenService.validateRefreshToken( logoutRequest, fingerprint.deviceId(), fingerprint.userAgent(), fingerprint.ipAddress());

		String hashedToken = SHA256TokenHash.hashToken(logoutRequest.refreshToken());

		transactionTemplate.executeWithoutResult(status -> {
			refreshTokenService.revokeToken(hashedToken);
		});

		return new LogoutResponse(" User logout successfully.");
	}

}
