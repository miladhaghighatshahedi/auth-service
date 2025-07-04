package com.mhs.authService.authentication.resolver;

import jakarta.servlet.http.HttpServletRequest;

public interface IpAddressResolver {
    String resolve(HttpServletRequest request);

}
