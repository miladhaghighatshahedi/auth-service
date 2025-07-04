package com.mhs.authService.authentication.security.ratelimit;

import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
public class IpIdentifierResolver implements IdentifierResolver{

	@Override
	public String resolve() {

		HttpServletRequest httpServletRequest = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

		String xfHeader = httpServletRequest.getHeader("X-Forwarded-For");
		return (xfHeader != null && !xfHeader.isBlank()) ? xfHeader.split(",")[0] : httpServletRequest.getRemoteAddr();
	}

	@Override
	public IdentifierType getType() {
		return IdentifierType.IP;
	}

}
