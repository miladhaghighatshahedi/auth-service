package com.mhs.authService.util.encoding;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CustomArgon2PasswordEncoder implements PasswordEncoder {

	private final Argon2PasswordEncoder passwordEncoder;

    public CustomArgon2PasswordEncoder(){
		this.passwordEncoder = new Argon2PasswordEncoder(16, 32, 4, 1<<16, 3);
    }

	@Override
	public String encode(CharSequence rawPassword) {
		return passwordEncoder.encode(rawPassword);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return passwordEncoder.matches(rawPassword,encodedPassword);
	}

}
