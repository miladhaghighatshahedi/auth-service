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
package com.mhs.authService.infrastructure.verification.otp;

import com.mhs.authService.infrastructure.verification.otp.exception.SmsOtpInvalidException;
import com.mhs.authService.infrastructure.verification.otp.exception.SmsOtpBlockedException;
import com.mhs.authService.infrastructure.verification.otp.exception.SmsOtpExpiredException;
import com.mhs.authService.infrastructure.verification.otp.store.SmsOtpStore;
import com.mhs.authService.infrastructure.verification.otp.strategy.SmsOtpSecurityCodeGenerator;
import com.mhs.authService.infrastructure.verification.otp.tracker.SmsOtpAttemptTracker;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.time.Duration;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("smsOtpVerificationGeneratorService")
@RequiredArgsConstructor
class SmsOtpVerificationGeneratorService implements SmsOtpVerificationGenerator {

	private final SmsOtpSecurityCodeGenerator smsOtpCodeGenerator;
	private final SmsOtpVerificationProperties smsOtpProperties;
	private final SmsOtpAttemptTracker attemptTracker;
	private final SmsOtpStore smsOtpStore;


	@Override
	public String generate(String mobile) {

		String otpCode = smsOtpCodeGenerator.generate();

		String key = smsOtpProperties.getPrefix() + mobile;
		smsOtpStore.store(key,otpCode,Duration.ofMinutes(smsOtpProperties.getTtl()));

		return otpCode;
	}

	@Override
	public void verify(String mobile, String retrievedCode) {

		if (attemptTracker.isBlocked(mobile)){
			throw new SmsOtpBlockedException("error: Too many failed attempts. Try again in a few minutes.");
		}

		String key = smsOtpProperties.getPrefix() + mobile;
		String storedOtpCode = smsOtpStore.retrieve(key).orElseThrow(() -> new SmsOtpExpiredException("error: OTP has expired."));

		if(!storedOtpCode.equals(retrievedCode)){
			attemptTracker.increment(mobile);
			throw new SmsOtpInvalidException("error: incorrect otpCode.");
		}

		smsOtpStore.remove(key);
		attemptTracker.reset(mobile);

	}

}
