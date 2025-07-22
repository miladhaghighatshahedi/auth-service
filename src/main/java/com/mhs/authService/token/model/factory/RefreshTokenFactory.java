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
package com.mhs.authService.token.model.factory;

import com.mhs.authService.iam.user.User;
import com.mhs.authService.token.model.RefreshToken;
import java.time.Instant;

/**
 * @author Milad Haghighat Shahedi
 */

public interface RefreshTokenFactory {

	 RefreshToken create( User user,
	                      String hashedToken,
	                      String deviceId,
	                      String userAgent,
	                      String ipAddress,
	                      Instant refreshTokenIssuedDate,
	                      Instant refreshTokenExpiryDate,
	                      boolean revoked);

}
