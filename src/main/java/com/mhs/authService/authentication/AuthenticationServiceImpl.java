package com.mhs.authService.authentication;

import com.mhs.authService.authentication.dto.AuthenticationRequest;
import com.mhs.authService.authentication.dto.AuthenticationResponse;
import com.mhs.authService.exception.error.RegistrationException;
import com.mhs.authService.iam.role.RoleService;
import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.UserService;
import com.mhs.authService.iam.user.factory.UserFactory;
import com.mhs.authService.token.dto.RefreshTokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import java.util.Set;

@Service
@AllArgsConstructor
class AuthenticationServiceImpl implements AuthenticationService{

	private final UserService userService;
	private final UserFactory userFactory;
	private final RoleService roleService;


	@Override
	public AuthenticationResponse register(AuthenticationRequest authenticationRequest) {

		String username = authenticationRequest.getUsername();
		String rawPassword = authenticationRequest.getPassword();

		if(userService.existsByUsername(username)){
			throw new DataIntegrityViolationException("error: username already taken!");
		}

		try{

			User user = userFactory.createUser(username, rawPassword, Set.of(roleService.findByName("ROLE_USER")));
			User savedUser = userService.save(user);

			return new AuthenticationResponse( null,
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
		return null;
	}

	@Override
	public AuthenticationResponse rotate(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {
		return null;
	}

	@Override
	public AuthenticationResponse logout(RefreshTokenRequest refreshTokenRequest, HttpServletRequest httpServletRequest) {
		return null;
	}
}
