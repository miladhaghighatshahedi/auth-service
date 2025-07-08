package com.mhs.authService.iam.user.matcher;

import com.mhs.authService.iam.user.enums.UsernameType;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
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
