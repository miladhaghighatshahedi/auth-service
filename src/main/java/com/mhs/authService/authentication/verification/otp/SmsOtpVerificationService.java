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

import com.mhs.authService.exception.error.OtpBlockedException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.time.Duration;

/**
 * @author Milad Haghighat Shahedi
 */

@Service
@AllArgsConstructor
class SmsOtpVerificationService implements SmsOtpVerificationGenerator{

	private final SmsOtpSecurityCodeGenerator smsOtpCodeGenerator;
	private final SmsOtpStore smsOtpStore;
	private final SmsOtpAttemptTracker attemptTracker;
	private final SmsOtpVerificationProperties smsOtpProperties;

	@Override
	public String generate(String mobile) {

		String otpCode = smsOtpCodeGenerator.generate();

		String key = smsOtpProperties.getPrefix() + mobile;
		smsOtpStore.store(key,otpCode,Duration.ofMinutes(smsOtpProperties.getTtl()));

		return otpCode;
	}

	@Override
	public boolean verify(String mobile, String retrievedCode) {

		if (attemptTracker.isBlocked(mobile)){
			throw new OtpBlockedException("Too many failed attempts. Try again in a few minutes.");
		}

		String key = smsOtpProperties.getPrefix() + mobile;

		return smsOtpStore.retrieve(key)
				.filter(otpCode -> otpCode.equals(retrievedCode))
				.map(match -> {
					smsOtpStore.remove(key);
					attemptTracker.reset(mobile);
					return true;
				})
				.orElseGet(() -> {
					attemptTracker.increment(mobile);
					return false;
				});
	}

}
