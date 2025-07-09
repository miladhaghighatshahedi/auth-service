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
import org.springframework.web.bind.annotation.ResponseBody;

@ResponseBody
@Controller("/auth")
@AllArgsConstructor

public class AuthenticationController {

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
