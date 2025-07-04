package com.mhs.authService.authentication.security.ratelimit;

import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class UserIdentifierResolver implements IdentifierResolver{

	@Override
	public String resolve() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return (auth != null && auth.isAuthenticated()) ? auth.getName() : "anonymous";
	}

	@Override
	public IdentifierType getType() {
		return IdentifierType.USER;
	}

}
