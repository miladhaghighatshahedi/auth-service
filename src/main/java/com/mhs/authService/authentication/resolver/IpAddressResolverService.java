package com.mhs.authService.authentication.resolver;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class IpAddressResolverService {

    private final IpAddressResolver ipAddressResolver;

    public String detect(HttpServletRequest request) {
        try {
            return ipAddressResolver.resolve(request);
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

}
