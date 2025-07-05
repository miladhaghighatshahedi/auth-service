package com.mhs.authService.token;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "token")
@Data
public class TokenProperties {

    private int accessTokenExpiryHours;
    private int refreshTokenExpiryHours;

    private int refreshTokenTimeFrameMinutes;

    private String accessTokenIssuer;
    private String accessTokenClaimType;

    private String refreshTokenIssuer;
    private String refreshTokenClaimType;

}
