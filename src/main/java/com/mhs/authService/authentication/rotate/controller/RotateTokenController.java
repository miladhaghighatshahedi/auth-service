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
package com.mhs.authService.authentication.rotate.controller;

import com.mhs.authService.authentication.rotate.RotateTokenService;
import com.mhs.authService.authentication.rotate.dto.RotateTokenRequest;
import com.mhs.authService.authentication.rotate.dto.RotateTokenResponse;
import com.mhs.authService.authentication.security.ratelimit.annotation.RateLimit;
import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author Milad Haghighat Shahedi
 */

@ResponseBody
@Controller
@RequiredArgsConstructor
public class RotateTokenController {

	private final RotateTokenService rotateTokenService;

	@RateLimit( key = "ROTATE_",
				maxRequests = 3,
				timeFrameInMinutes = 15,
				identifiers = {IdentifierType.USER, IdentifierType.IP})
	@PostMapping("/auth/rotate")
	public ResponseEntity<RotateTokenResponse> refreshToken(@RequestBody RotateTokenRequest rotateTokenRequest, HttpServletRequest httpServletRequest) {
		return ResponseEntity.ok(rotateTokenService.rotate(rotateTokenRequest,httpServletRequest));
	}

}
