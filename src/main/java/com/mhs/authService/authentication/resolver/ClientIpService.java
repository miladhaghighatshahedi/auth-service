package com.mhs.authService.authentication.resolver;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class ClientIpService {

    private final IpAddressResolver ipAddressResolver;

    public String detect(HttpServletRequest request) {
        try {
            return ipAddressResolver.resolve(request);
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

}
