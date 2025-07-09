package com.mhs.authService.authentication;

import com.mhs.authService.authentication.dto.AuthenticationRequest;
import com.mhs.authService.authentication.dto.AuthenticationResponse;
import com.mhs.authService.authentication.resolver.IpAddressResolverService;
import com.mhs.authService.exception.error.RegistrationException;
import com.mhs.authService.iam.role.RoleService;
import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.UserService;
import com.mhs.authService.iam.user.factory.UserFactory;
import com.mhs.authService.token.JwtTokenUtil;
import com.mhs.authService.token.dto.RefreshTokenRequest;
import com.mhs.authService.token.model.RefreshTokenService;
import com.mhs.authService.util.hash.HashService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

@Service
@AllArgsConstructor
class AuthenticationServiceImpl implements AuthenticationService{

	private final UserService userService;
	private final UserFactory userFactory;
	private final RoleService roleService;
	private final HashService hashService;
	private final JwtTokenUtil jwtTokenUtil;
	private final RefreshTokenService refreshTokenService;
	private final AuthenticationManager authenticationManager;
    private final IpAddressResolverService ipAddressResolverService;

	@Override
	public AuthenticationResponse register(AuthenticationRequest authenticationRequest,HttpServletRequest httpServletRequest) {

		String username = authenticationRequest.getUsername();
		String rawPassword = authenticationRequest.getPassword();

		if(userService.existsByUsername(username)){
			throw new DataIntegrityViolationException("error: username already taken!");
		}

		try{

			User user = userFactory.createUser(username, rawPassword, Set.of(roleService.findByName("ROLE_USER")));
			User savedUser = userService.save(user);

			return new AuthenticationResponse(
					null,
					null,
					null,
					savedUser.getUsername(),
					null,
					"User registered successfully!");

		}catch (DataAccessException exception){
			throw new RegistrationException("error: Database error occurred during registration. Please try again later.");
		}catch (Exception exception) {
			throw new RegistrationException("error: Registration failed due to an internal error.");
		}

	}

	@Override
	public AuthenticationResponse login(AuthenticationRequest authenticationRequest,HttpServletRequest httpServletRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
		);

		String ipAddress = ipAddressResolverService.detect(httpServletRequest);
		String deviceId  = httpServletRequest.getHeader("X-Device-Id");
		String userAgent = httpServletRequest.getHeader("User-Agent");

		String accessToken  = jwtTokenUtil.generateAccessToken(authentication, deviceId, userAgent, ipAddress);
		String refreshToken = jwtTokenUtil.generateRefreshToken(authentication, deviceId, userAgent, ipAddress);

		String hashedToken = hashService.hashToken(refreshToken);

		refreshTokenService.saveRefreshToken(
				authentication.getName(),
				hashedToken,
				deviceId,
				userAgent,
				ipAddress,
				Instant.now(),
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getRefreshTokenExpiryHours(), ChronoUnit.HOURS));

		return new AuthenticationResponse(
				accessToken,
				refreshToken,
				Instant.now().plus(jwtTokenUtil.getTokenProperties().getAccessTokenExpiryHours(), ChronoUnit.HOURS),
				authenticationRequest.getUsername(),
				new HashSet<>(authentication.getAuthorities()),
				"User logged successfully.");
	}

	@Override
	public AuthenticationResponse rotate(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {
		return null;
	}

	@Override
	public AuthenticationResponse logout(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {

		String ipAddress = ipAddressResolverService.detect(httpServletRequest);
		String userAgent = httpServletRequest.getHeader("User-Agent");
		String deviceId  = httpServletRequest.getHeader("X-Device-Id");

		jwtTokenUtil.validateRefreshToken(refreshTokenRequest,deviceId,userAgent,ipAddress);

		String hashedToken = hashService.hashToken(refreshTokenRequest.refreshToken());

		refreshTokenService.revokeToken(hashedToken);

		return new AuthenticationResponse(
				null,
				null,
				null,
				null,
				null,
				"User logout successfully.");
	}

}
