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

/**
 *
 * @author Milad Haghighat Shahedi
 */

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
