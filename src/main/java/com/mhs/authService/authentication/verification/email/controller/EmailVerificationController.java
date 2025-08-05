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
package com.mhs.authService.authentication.verification.email.controller;

import com.mhs.authService.authentication.verification.email.EmailVerificationService;
import com.mhs.authService.authentication.verification.email.dto.EmailVerificationResponse;
import com.mhs.authService.infrastructure.ratelimit.annotation.RateLimit;
import com.mhs.authService.infrastructure.ratelimit.enums.IdentifierType;
import com.mhs.authService.infrastructure.validation.annotation.ValidJwtToken;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author Milad Haghighat Shahedi
 */

@ResponseBody
@Controller
@Validated
@RequiredArgsConstructor
public class EmailVerificationController {

	private final EmailVerificationService verifyEmailService;

	@RateLimit( key = "EMAIL_VERIFICATION_",
			maxRequests = 3,
			timeFrameInMinutes = 60,
			identifiers = {IdentifierType.IP})
	@GetMapping("/auth/email/verify")
	public ResponseEntity<EmailVerificationResponse> verify(
			@RequestParam("token")
			@ValidJwtToken
			String token) {
		return ResponseEntity.ok(verifyEmailService.verify(token));
	}

}
