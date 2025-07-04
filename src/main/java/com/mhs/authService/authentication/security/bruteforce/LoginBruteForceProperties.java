package com.mhs.authService.authentication.security.bruteforce;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "auth.security.brute-force.login")
@Data
public class LoginBruteForceProperties {

    private  int maxAttempts;
    private  int banDurationMinutes;
    private  String userAttemptKeyPrefix;
    private  String userBlockKeyPrefix;
    private  String ipAttemptKeyPrefix;
    private  String ipBlockKeyPrefix;

}
