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
package com.mhs.authService.authentication;

import com.mhs.authService.authentication.dto.AuthenticationRequest;
import com.mhs.authService.authentication.dto.AuthenticationResponse;
import com.mhs.authService.authentication.dto.LogoutResponse;
import com.mhs.authService.authentication.dto.RegistrationResponse;
import com.mhs.authService.authentication.security.ratelimit.annotation.RateLimit;
import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;
import com.mhs.authService.token.dto.RefreshTokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author Milad Haghighat Shahedi
 */

@ResponseBody
@Controller
@RequestMapping("/auth")
@AllArgsConstructor
class AuthenticationController {

	private final AuthenticationService authenticationService;


	@RateLimit( key = "REGISTER_", maxRequests = 3, timeFrameInMinutes = 60, identifiers = {IdentifierType.IP})
	@PostMapping("/register")
	public ResponseEntity<RegistrationResponse> register(@Valid @RequestBody AuthenticationRequest authenticationRequest, HttpServletRequest httpServletRequest){
		return ResponseEntity.status(HttpStatus.CREATED).body(authenticationService.register(authenticationRequest,httpServletRequest));
	}

	@RateLimit( key = "LOGIN_", maxRequests = 3, timeFrameInMinutes = 15, identifiers = {IdentifierType.IP})
	@PostMapping("/login")
	public ResponseEntity<AuthenticationResponse> login( @RequestBody AuthenticationRequest authenticationRequest, HttpServletRequest httpServletRequest) {
		return ResponseEntity.ok(authenticationService.login(authenticationRequest,httpServletRequest));
	}


	@RateLimit( key = "ROTATE_", maxRequests = 3, timeFrameInMinutes = 15, identifiers = {IdentifierType.USER, IdentifierType.IP})
	@PostMapping("/rotate")
	public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {
		return ResponseEntity.ok(authenticationService.rotate(refreshTokenRequest,httpServletRequest));
	}

	@RateLimit( key = "LOGOUT_", maxRequests = 3, timeFrameInMinutes = 15, identifiers = {IdentifierType.USER, IdentifierType.IP})
	@PostMapping("/logout")
	public ResponseEntity<LogoutResponse> logout(@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {
		return ResponseEntity.ok(authenticationService.logout(refreshTokenRequest,httpServletRequest));
	}

}
