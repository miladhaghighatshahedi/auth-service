package com.mhs.authService.iam.user.matcher;

import com.mhs.authService.iam.user.enums.UsernameType;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
@AllArgsConstructor
public class UsernameTypeMatcherService {

    private final List<UsernameTypeMatcher> matchers;

    public UsernameType determine(String username){

        if(username == null || username.isBlank()) {
            throw new IllegalArgumentException("error: Username is null or blank.");
        }

        return matchers.stream()
                .filter(matcher -> matcher.determine(username))
                .findFirst()
                .map(UsernameTypeMatcher::getType)
                .orElseThrow(() ->   new IllegalArgumentException("error: Username is not a valid email or mobile number."));
    }

}

