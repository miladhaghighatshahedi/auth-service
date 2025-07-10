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
package com.mhs.authService.authentication.security.bruteforce;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 *
 * @author Milad Haghighat Shahedi
 */

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
