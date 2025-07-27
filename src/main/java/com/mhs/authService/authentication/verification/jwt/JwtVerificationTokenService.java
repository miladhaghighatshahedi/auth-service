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
package com.mhs.authService.authentication.verification.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

/**
 * @author Milad Haghighat Shahedi
 */

@Service
@AllArgsConstructor
class JwtVerificationTokenService implements JwtVerificationTokenGenerator {

	private final JwtVerificationTokenProperties tokenProperties;

	@Override
	public String generate(String email) {
		return Jwts.builder()
				.subject(email)
				.issuedAt(Date.from(Instant.now()))
				.expiration(Date.from(Instant.now().plus(Duration.ofMinutes(tokenProperties.getExpirationTime()))))
				.claim("email",email)
				.claim("type",tokenProperties.getTokenType())
				.signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenProperties.getSecretString())))
				.compact();
	}

	@Override
	public boolean validate(String token) {
		try {
			Jwts.parser()
				.verifyWith(Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(tokenProperties.getSecretString())))
				.build()
				.parseSignedClaims(token);
				return true;
		}catch (ExpiredJwtException |
		        UnsupportedJwtException |
		        MalformedJwtException |
		        SecurityException |
		        IllegalArgumentException e){
				return false;
		}
	}

	public String extractUsername(String token){
		return Jwts.parser()
				.verifyWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenProperties.getSecretString())))
				.build()
				.parseSignedClaims(token)
				.getPayload()
				.getSubject();
	}

}
