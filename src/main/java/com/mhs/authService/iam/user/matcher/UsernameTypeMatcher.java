package com.mhs.authService.iam.user.matcher;

import com.mhs.authService.iam.user.enums.UsernameType;

public interface UsernameTypeMatcher {

    boolean determine(String input);
    UsernameType getType();

}
