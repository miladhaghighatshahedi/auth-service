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
package com.mhs.authService.exception.handler;

import com.mhs.authService.exception.error.*;
import com.mhs.authService.exception.model.ExceptionResponse;
import com.mhs.authService.util.validation.dto.ValidationError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 *
 * @author Milad Haghighat Shahedi
 */

@RestControllerAdvice
public class CentralExceptionHandler {

	@ExceptionHandler(DuplicateEntityException.class)
	public ResponseEntity<ExceptionResponse> handleDuplicateEntity(DuplicateEntityException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.CONFLICT.value(),
				false);
		return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
	}

	@ExceptionHandler(EntityCreationException.class)
	public ResponseEntity<ExceptionResponse> handleEntityCreation(EntityCreationException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.CONFLICT.value(),
				false);
		return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
	}

	@ExceptionHandler(RegistrationException.class)
	public ResponseEntity<ExceptionResponse> handleRegistrationException(RegistrationException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.INTERNAL_SERVER_ERROR.value(),
				false);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	}

	@ExceptionHandler(InvalidTokenException.class)
	public ResponseEntity<String> handleInvalidTokenException(InvalidTokenException ex) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
	}

	@ExceptionHandler(RateLimitExceededException.class)
	public ResponseEntity<String> handleRateLimitExceededException(RateLimitExceededException ex) {
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(ex.getMessage());
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, List<String>>> handleMethodArgumentNotValidException(MethodArgumentNotValidException exception) {
		Map<String, List<String>> errors = exception.getBindingResult()
				.getFieldErrors()
				.stream()
				.collect(Collectors.groupingBy(
						FieldError::getField,
						Collectors.mapping(
								FieldError::getDefaultMessage,
								Collectors.toList())
				));
		return ResponseEntity.badRequest().body(errors);
	}

	@ExceptionHandler(CredentialValidationException.class)
	public ResponseEntity<List<ValidationError>> handleCredentialValidationException(CredentialValidationException ex) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getErrors());
	}

}
