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
import com.mhs.authService.token.dto.RefreshTokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@ResponseBody
@Controller
@RequestMapping("/auth")
@AllArgsConstructor
class AuthenticationController {

	private final AuthenticationService authenticationService;

	@PostMapping("/register")
	public ResponseEntity<AuthenticationResponse> register(@RequestBody AuthenticationRequest authenticationRequest,HttpServletRequest httpServletRequest){
		return ResponseEntity.ok(authenticationService.register(authenticationRequest,httpServletRequest));
	}

	@PostMapping("/login")
	public ResponseEntity<AuthenticationResponse> login( @RequestBody AuthenticationRequest authenticationRequest, HttpServletRequest httpServletRequest) {
		return ResponseEntity.ok(authenticationService.login(authenticationRequest,httpServletRequest));
	}

	@PostMapping("/rotate")
	public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {
		return ResponseEntity.ok(authenticationService.rotate(refreshTokenRequest,httpServletRequest));
	}

	@PostMapping("/logout")
	public ResponseEntity<AuthenticationResponse> logout( @RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {
		return ResponseEntity.ok(authenticationService.logout(refreshTokenRequest,httpServletRequest));
	}

}
