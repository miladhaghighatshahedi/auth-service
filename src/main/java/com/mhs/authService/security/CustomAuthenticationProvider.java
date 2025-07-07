package com.mhs.authService.security;

import com.mhs.authService.util.encoding.CustomArgon2PasswordEncoder;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final CustomUserDetailsService userDetailsService;
	private final CustomArgon2PasswordEncoder passwordEncoder;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String rawPassword = authentication.getCredentials().toString();

		try{
			CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(username);
			String encryptedPassword = userDetails.getPassword();

			if(!passwordEncoder.matches(rawPassword,encryptedPassword)){
				throw new BadCredentialsException("error: Invalid Credentials.");
			}

			if(!userDetails.isEnabled()){
				throw new BadCredentialsException("error: User account is disabled.");
			}

			if(!userDetails.isAccountNonLocked()){
				throw new BadCredentialsException("error: User account is locked.");
			}

			return new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

		}catch (UsernameNotFoundException exception){
			throw new BadCredentialsException("error: Invalid Credentials.");
		}

	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
