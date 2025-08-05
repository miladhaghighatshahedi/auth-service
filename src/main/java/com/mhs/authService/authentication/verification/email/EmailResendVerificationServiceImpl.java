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
package com.mhs.authService.authentication.verification.email;

import com.mhs.authService.authentication.verification.email.dto.EmailResendVerificationRequest;
import com.mhs.authService.authentication.verification.email.dto.EmailResendVerificationResponse;
import com.mhs.authService.authentication.verification.email.ratelimit.EmailResendVerificationRateLimiterService;
import com.mhs.authService.infrastructure.verification.dto.VerificationPayload;
import com.mhs.authService.infrastructure.verification.exception.UserAlreadyVerifiedException;
import com.mhs.authService.infrastructure.verification.strategy.VerificationStrategyResolverService;
import com.mhs.authService.user.User;
import com.mhs.authService.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("emailResendVerificationService")
@RequiredArgsConstructor
public class EmailResendVerificationServiceImpl implements EmailResendVerificationService {

	private final UserService userService;
	private final EmailResendVerificationRateLimiterService emailResendVerificationRateLimiterService;
	private final VerificationStrategyResolverService verificationStrategyResolve;


	@Override
	public EmailResendVerificationResponse resend(EmailResendVerificationRequest emailResendVerificationRequest) {

		String email = emailResendVerificationRequest.email();

		emailResendVerificationRateLimiterService.resendVerificationAllowed(email);

		User user = userService.findByUsername(email);
		if(user.isEnabled()){
			throw new UserAlreadyVerifiedException("error: user already verified.");
		}

		VerificationPayload verificationPayload = verificationStrategyResolve.generatePayLoad(user.getUsername(), user.getUsernameType());
		System.out.println(verificationPayload);

		return new EmailResendVerificationResponse(email,"email resent successfully.");
	}

}
