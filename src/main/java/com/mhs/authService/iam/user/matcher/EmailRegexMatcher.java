package com.mhs.authService.iam.user.matcher;

import com.mhs.authService.iam.user.enums.UsernameType;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
public class EmailRegexMatcher implements UsernameTypeMatcher {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$",Pattern.CASE_INSENSITIVE);

    @Override
    public boolean determine(String input) {
        return EMAIL_PATTERN.matcher(input).matches();
    }

    @Override
    public UsernameType getType() {
        return UsernameType.EMAIL;
    }

}
