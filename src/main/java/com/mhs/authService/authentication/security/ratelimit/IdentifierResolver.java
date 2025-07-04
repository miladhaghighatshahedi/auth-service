package com.mhs.authService.authentication.security.ratelimit;

import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;

public interface IdentifierResolver {
	String resolve();
	IdentifierType getType();
}
