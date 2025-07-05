package com.mhs.authService.util.hash;

public interface HashStrategy {

	String hashToken(String rawToken);

	boolean verifyToken(String rawToken,String hashedToken);

}
