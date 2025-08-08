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
package com.mhs.authService.common.ip;

import com.mhs.authService.common.ip.strategy.IpAddressResolver;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@Service("ipAddressResolverService")
@RequiredArgsConstructor
class IpAddressResolverServiceImpl implements IpAddressResolverService{

    private final IpAddressResolver ipAddressResolver;

    public String detect(HttpServletRequest request) {
        try {
            return ipAddressResolver.resolve(request);
        } catch (Exception e) {
            return "UNKNOWN_IP_ADDRESS";
        }
    }

}
