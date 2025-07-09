package com.mhs.authService.authentication.resolver;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
class XFHeaderIpAddressResolver implements IpAddressResolver {

    @Override
    public String resolve(HttpServletRequest httpServletRequest) {
        String xfHeader = httpServletRequest.getHeader("X-Forwarded-For");
        return (xfHeader != null && !xfHeader.isBlank()) ? xfHeader.split(",")[0].trim() :  httpServletRequest.getRemoteAddr();
    }

}
