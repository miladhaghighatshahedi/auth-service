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
package com.mhs.authService.authentication.security.ratelimit;

import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;
import com.mhs.authService.authentication.security.ratelimit.resolver.IdentifierResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.Arrays;
import java.util.List;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@RequiredArgsConstructor
class RateLimiterKeyBuilder {

    private final List<IdentifierResolver> resolvers;

    public String buildCompositeKey(IdentifierType[] types){
        List<String> components = Arrays.stream(types)
                .map(this::resolveIdentifier)
                .toList();
        return String.join("_",components);
    }

    public String resolveIdentifier(IdentifierType type){
       return resolvers.stream()
                .filter(resolver -> resolver.getType() == type)
                .findFirst()
                .orElseThrow(() ->  new IllegalArgumentException("error: Unknown identifier type "+type))
                .resolve();
    }

}
