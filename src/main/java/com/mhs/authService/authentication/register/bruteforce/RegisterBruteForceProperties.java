package com.mhs.authService.authentication.register.bruteforce;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "auth.security.brute-force.register")
@Data
public class RegisterBruteForceProperties {

    private  int maxAttempts;
    private  int banDurationMinutes;
    private  String ipAttemptKeyPrefix;
    private  String ipBlockKeyPrefix;

}
