package com.mhs.authService.iam.user.factory;

import com.mhs.authService.iam.role.Role;
import com.mhs.authService.iam.user.User;
import java.util.Set;

public interface UserFactory {
	User createUser(String username, String password, Set<Role> role);

}
