package com.mhs.authService.security;

import com.mhs.authService.iam.user.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Set;

@Data
public class CustomUserDetails implements UserDetails {

	private final String username;
	private final String password;
	private final Set<? extends GrantedAuthority> authorities;
	private final boolean accountNonExpired;
	private final boolean accountNonLocked;
	private final boolean credentialsNonExpired;
	private final boolean enabled;

	public CustomUserDetails(User user) {
		this.username = user.getUsername();
		this.password = user.getPassword();
		this.authorities = CustomGrantedAuthority.getAuthorities(user.getRoles());
		this.accountNonExpired = true;
		this.credentialsNonExpired = true;
		this.accountNonLocked = true;
		this.enabled = true;
	}

}
