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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * @author Milad Haghighat Shahedi
 */

public interface JwtVerificationTokenGenerator {

	String generate(String email);

	Jws<Claims> verify(String token);

	String extractUsername(String token);

}
