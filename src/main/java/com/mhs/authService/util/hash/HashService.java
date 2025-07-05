package com.mhs.authService.util.hash;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class HashService {

	private final HashStrategy hashStrategy;

	public String hashToken(String token){
		return hashStrategy.hashToken(token);
	}

	public boolean verifyToken(String rawToken,String hashedToken){
		return hashStrategy.verifyToken(rawToken,hashedToken);
	}
}
