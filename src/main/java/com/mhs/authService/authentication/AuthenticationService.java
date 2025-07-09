package com.mhs.authService.authentication;

import com.mhs.authService.authentication.dto.AuthenticationRequest;
import com.mhs.authService.authentication.dto.AuthenticationResponse;
import com.mhs.authService.token.dto.RefreshTokenRequest;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthenticationService {

	AuthenticationResponse register(AuthenticationRequest authenticationRequest,HttpServletRequest httpServletRequest);
	AuthenticationResponse login(AuthenticationRequest authenticationRequest,HttpServletRequest httpServletRequest);
	AuthenticationResponse rotate(RefreshTokenRequest refreshTokenRequest,HttpServletRequest httpServletRequest);
	AuthenticationResponse logout(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest);

}
