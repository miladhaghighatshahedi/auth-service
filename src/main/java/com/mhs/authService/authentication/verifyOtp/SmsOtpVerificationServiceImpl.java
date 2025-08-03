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
package com.mhs.authService.authentication.verifyOtp;

import com.mhs.authService.authentication.verification.otp.SmsOtpVerificationGenerator;
import com.mhs.authService.authentication.verifyEmail.exception.EmailVerificationException;
import com.mhs.authService.authentication.verification.exception.UserAlreadyVerifiedException;
import com.mhs.authService.authentication.verifyOtp.dto.SmsOtpVerificationRequest;
import com.mhs.authService.authentication.verifyOtp.dto.SmsOtpVerificationResponse;
import com.mhs.authService.user.User;
import com.mhs.authService.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * @author Milad Haghighat Shahedi
 */

@Service("SmsOtpVerificationService")
@RequiredArgsConstructor
class SmsOtpVerificationServiceImpl implements SmsOtpVerificationService {

	private final UserService userService;
	private final TransactionTemplate transactionTemplate;
	private final SmsOtpVerificationGenerator smsOtpVerificationGenerator;

	@Override
	public SmsOtpVerificationResponse verify(SmsOtpVerificationRequest smsOtpVerificationRequest) {

		User user = userService.findByUsername(smsOtpVerificationRequest.mobile());
		if(user.isEnabled()){
			throw new UserAlreadyVerifiedException("user already verified.");
		}

		try {
			return transactionTemplate.execute(status -> {
				try {
					userService.enableByUsername(smsOtpVerificationRequest.mobile());
					smsOtpVerificationGenerator.verify(smsOtpVerificationRequest.mobile(), smsOtpVerificationRequest.otpCode());
					return new SmsOtpVerificationResponse(smsOtpVerificationRequest.mobile(), "user successfully verified!");
				} catch (DataAccessException e) {
					throw new EmailVerificationException("error: Database error occurred during verification. Please try again later.");
				}
			});
		} catch (TransactionException e) {
			throw new EmailVerificationException("Error: Unable to verify user due to transaction failure.");
		}

	}
}
