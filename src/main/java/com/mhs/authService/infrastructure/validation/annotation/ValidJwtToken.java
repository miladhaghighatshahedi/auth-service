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
package com.mhs.authService.infrastructure.validation.annotation;

import com.mhs.authService.infrastructure.validation.validator.JwtTokenConstraintValidator;
import jakarta.validation.Constraint;
import org.springframework.messaging.handler.annotation.Payload;
import java.lang.annotation.*;

/**
 * @author Milad Haghighat Shahedi
 */

@Target({ ElementType.PARAMETER, ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = JwtTokenConstraintValidator.class)
public @interface ValidJwtToken {

	String message() default "Invalid JWT token";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

}
