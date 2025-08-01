/*
 * Copyright 2025-2026 the original author.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mhs.authService.infrastructure.hash.strategy;

import io.micrometer.common.util.StringUtils;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 *
 * @author Milad Haghighat Shahedi
 */

// caution it has work to do
@Component
@Primary
class SHA256TokenHashingStrategy implements TokenHashingStrategy {

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
