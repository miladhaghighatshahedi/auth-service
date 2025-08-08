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
package com.mhs.authService.authentication.verification.otp;

import com.mhs.authService.authentication.verification.otp.dto.SmsOtpResendVerificationRequest;
import com.mhs.authService.authentication.verification.otp.dto.SmsOtpResendVerificationResponse;
import com.mhs.authService.authentication.verification.otp.ratelimit.SmsOtpResendVerificationRateLimiterService;
import com.mhs.authService.common.verification.exception.UserAlreadyVerifiedException;
import com.mhs.authService.common.verification.strategy.VerificationStrategyResolverService;
import com.mhs.authService.user.User;
import com.mhs.authService.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("SmsOtpResendVerificationService")
@RequiredArgsConstructor
class SmsOtpResendVerificationServiceImpl implements SmsOtpResendVerificationService{

	private final UserService userService;
	private final VerificationStrategyResolverService verificationStrategyResolver;
	private final SmsOtpResendVerificationRateLimiterService smsOtpResendVerificationRateLimiterService;

	@Override
	public SmsOtpResendVerificationResponse resend(SmsOtpResendVerificationRequest smsOtpResendVerificationRequest) {

		String mobile = smsOtpResendVerificationRequest.mobile();

		smsOtpResendVerificationRateLimiterService.resendVerificationAllowed(mobile);

		User user = userService.findByUsername(mobile);
		if(user.isEnabled()){
			throw new UserAlreadyVerifiedException("error: user already verified.");
		}

		verificationStrategyResolver.generatePayLoad(user.getUsername(), user.getUsernameType());

		return new SmsOtpResendVerificationResponse(mobile,"Sms Otp resent successfully.");
	}

}
