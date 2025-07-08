package com.mhs.authService.iam.user.factory;

import com.mhs.authService.iam.role.Role;
import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.builder.UserBuilder;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.Set;

@Component
@AllArgsConstructor
public class DefaultUserFactory implements UserFactory{

    private final UserBuilder userBuilder;

    @Override
    public User createUser(String username, String password, Set<Role> roles){
        return userBuilder.build(username,password,roles);
    }

}
