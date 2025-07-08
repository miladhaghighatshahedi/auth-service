package com.mhs.authService.iam.user.builder;

import com.mhs.authService.iam.role.Role;
import com.mhs.authService.iam.user.User;
import com.mhs.authService.iam.user.enums.UsernameType;
import com.mhs.authService.iam.user.matcher.UsernameTypeMatcherService;
import com.mhs.authService.util.encoding.CustomArgon2PasswordEncoder;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import java.time.LocalDateTime;
import java.util.Set;

@Component
@AllArgsConstructor
public class UserBuilder {

	private final CustomArgon2PasswordEncoder passwordEncoder;
	private final UsernameTypeMatcherService usernameTypeMatcherService;

	public User build(String username, String password, Set<Role> roles){

		UsernameType usernameType = usernameTypeMatcherService.determine(username);
		String encodedPassword = passwordEncoder.encode(password);

		return User.builder()
				.username(username)
				.usernameType(usernameType)
				.password(encodedPassword)
				.joinedDate(LocalDateTime.now())
				.roles(roles)
				.build();
	}

}
