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
package com.mhs.authService.authentication.security.fingerprint;

import com.mhs.authService.infrastructure.ip.IpAddressResolverService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.Optional;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
@RequiredArgsConstructor
class RequestFingerPrintExtractorService implements RequestFingerprintExtractor {

	private final IpAddressResolverService ipAddressResolverService;

	@Override
	public RequestFingerprint extractFrom(HttpServletRequest httpServletRequest) {

		String ipAddress = ipAddressResolverService.detect(httpServletRequest);

		String deviceId = Optional.ofNullable(httpServletRequest.getHeader("X-Device-Id"))
				.filter(id -> !id.isBlank())
				.orElse("UNKNOWN_DEVICE_ID");

		String userAgent = Optional.ofNullable(httpServletRequest.getHeader("User-Agent"))
				.filter(agent -> !agent.isBlank())
				.orElse("UNKNOWN_USER_AGENT");

		return new RequestFingerprint(deviceId,ipAddress,userAgent);
	}

}
