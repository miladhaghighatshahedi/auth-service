package com.mhs.authService.authentication.security.ratelimit.annotation;

import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {

    String key();
    int maxRequests();
    int timeFrameInMinutes();
    IdentifierType[] identifiers();

}
