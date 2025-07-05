package com.mhs.authService.util.hash;

import io.micrometer.common.util.StringUtils;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

// caution it has work to do
@Component
@Primary
class SHA256TokenHash implements HashStrategy {

    public String hashToken(String rawToken) {

        if (rawToken == null || StringUtils.isBlank(rawToken)) {
            throw new IllegalArgumentException("error: Raw token cannot be null or blank.");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Error: SHA-256 not available.");
        }

    }

    public boolean verifyToken(String rawToken,String hashedToken){
        return hashToken(rawToken).equals(hashedToken);
    }

}
