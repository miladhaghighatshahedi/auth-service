package com.mhs.authService.authentication.security.ratelimit;

import com.mhs.authService.authentication.security.ratelimit.enums.IdentifierType;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.Arrays;
import java.util.List;

@Component
@AllArgsConstructor
public class RateLimiterKeyBuilder {

    private final List<IdentifierResolver> resolvers;

    public String buildCompositeKey(IdentifierType[] types){
        List<String> components = Arrays.stream(types)
                .map(type -> resolveIdentifier(type))
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
