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
package com.mhs.authService.infrastructure.identifier.matcher;

import com.mhs.authService.user.enums.UsernameType;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@Qualifier("mobileRegexMatcher")
public class MobileRegexMatcher implements UsernameTypeMatcher {

    private static final Pattern MOBILE_NUMBER_PATTERN = Pattern.compile("^09(0[1-5]|[1-3]\\d|2[0-2]|98)\\d{7}$");

    @Override
    public boolean determine(String mobile) {
        return MOBILE_NUMBER_PATTERN.matcher(mobile).matches();
    }

    @Override
    public UsernameType getType() {
        return UsernameType.MOBILE_NUMBER;
    }

}
