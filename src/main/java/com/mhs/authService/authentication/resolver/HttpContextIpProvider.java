package com.mhs.authService.authentication.resolver;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
@AllArgsConstructor
public final class HttpContextIpProvider {

    private final ClientIpService clientIpService;

    public String detect() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        return clientIpService.detect(request);
    }

}
