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
package com.mhs.authService.common.ratelimit.resolver;

import com.mhs.authService.common.ratelimit.enums.IdentifierType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * @author Milad Haghighat Shahedi
 */

@Component
class IpIdentifierResolver implements IdentifierResolver{

	@Override
	public String resolve() {

		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

		if (requestAttributes == null) {
			throw new IllegalStateException("error: No request bound to current thread");
		}

		HttpServletRequest httpServletRequest = requestAttributes.getRequest();

		String xfHeader = httpServletRequest.getHeader("X-Forwarded-For");
		return (xfHeader != null && !xfHeader.isBlank()) ? xfHeader.split(",")[0] : httpServletRequest.getRemoteAddr();
	}

	@Override
	public IdentifierType getType() {
		return IdentifierType.IP;
	}

}
