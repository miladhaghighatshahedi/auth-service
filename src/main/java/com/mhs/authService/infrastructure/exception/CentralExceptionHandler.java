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
package com.mhs.authService.infrastructure.exception;

import com.mhs.authService.authentication.register.exception.CredentialValidationException;
import com.mhs.authService.authentication.register.exception.RegistrationException;
import com.mhs.authService.authentication.verification.email.exception.EmailTooManyRequestException;
import com.mhs.authService.authentication.verification.otp.exception.SmsOtpTooManyRequestException;
import com.mhs.authService.authentication.verification.otp.exception.SmsOtpVerificationException;
import com.mhs.authService.infrastructure.verification.jwt.exception.InvalidVerificationTokenException;
import com.mhs.authService.infrastructure.verification.jwt.exception.VerificationTokenExpiredException;
import com.mhs.authService.infrastructure.verification.otp.exception.SmsOtpInvalidException;
import com.mhs.authService.infrastructure.verification.otp.exception.SmsOtpBlockedException;
import com.mhs.authService.infrastructure.ratelimit.exception.RateLimitExceededException;
import com.mhs.authService.infrastructure.verification.otp.exception.SmsOtpExpiredException;
import com.mhs.authService.authentication.verification.email.exception.EmailVerificationException;
import com.mhs.authService.infrastructure.verification.exception.UserAlreadyVerifiedException;
import com.mhs.authService.infrastructure.validation.dto.ValidationError;
import com.mhs.authService.iam.permission.exception.PermissionAlreadyExistsException;
import com.mhs.authService.iam.permission.exception.PermissionNotFoundException;
import com.mhs.authService.iam.role.exception.RoleCreationException;
import com.mhs.authService.iam.role.exception.RoleNotFoundException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
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

	@ExceptionHandler(PermissionAlreadyExistsException.class)
	public ResponseEntity<ExceptionResponse> handlePermissionAlreadyExistsException(PermissionAlreadyExistsException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.CONFLICT.value(),
				false);
		return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
	}

	@ExceptionHandler(PermissionNotFoundException.class)
	public ResponseEntity<ExceptionResponse> handlePermissionNotFoundException(PermissionNotFoundException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.NOT_FOUND.value(),
				false);
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
	}

	@ExceptionHandler(RoleNotFoundException.class)
	public ResponseEntity<ExceptionResponse> handleRoleNotFoundException(RoleNotFoundException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.NOT_FOUND.value(),
				false);
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
	}

	@ExceptionHandler(RoleCreationException.class)
	public ResponseEntity<ExceptionResponse> handleRoleCreationException(RoleCreationException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.CONFLICT.value(),
				false);
		return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
	}

	@ExceptionHandler(UsernameNotFoundException.class)
	public ResponseEntity<ExceptionResponse> handleUsernameNotFoundException(UsernameNotFoundException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.NOT_FOUND.value(),
				false);
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
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

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException exception) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(exception.getMessage());
	}

	@ExceptionHandler(CredentialValidationException.class)
	public ResponseEntity<List<ValidationError>> handleCredentialValidationException(CredentialValidationException ex) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getErrors());
	}

	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<ExceptionResponse> handleBadCredentialException(BadCredentialsException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.UNAUTHORIZED.value(),
				false);
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
	}

	@ExceptionHandler(LockedException.class)
	public ResponseEntity<ExceptionResponse> handleLockedException(LockedException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.LOCKED.value(),
				false);
		return ResponseEntity.status(HttpStatus.LOCKED).body(errorResponse);
	}

	@ExceptionHandler(SmsOtpBlockedException.class)
	public ResponseEntity<ExceptionResponse> handleOtpBlockedException(SmsOtpBlockedException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.TOO_MANY_REQUESTS.value(),
				false);
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
	}

	@ExceptionHandler(SmsOtpExpiredException.class)
	public ResponseEntity<ExceptionResponse> handleOtpExpiredException(SmsOtpExpiredException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.UNAUTHORIZED.value(),
				false);
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
	}

	@ExceptionHandler(SmsOtpInvalidException.class)
	public ResponseEntity<ExceptionResponse> handleInvalidOtpException(SmsOtpInvalidException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.BAD_REQUEST.value(),
				false);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
	}

	@ExceptionHandler(SmsOtpTooManyRequestException.class)
	public ResponseEntity<ExceptionResponse> handleSmsOtpTooManyRequestException(SmsOtpTooManyRequestException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.TOO_MANY_REQUESTS.value(),
				false);
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
	}

	@ExceptionHandler(SmsOtpVerificationException.class)
	public ResponseEntity<ExceptionResponse> handleSmsOtpVerificationException(SmsOtpVerificationException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.TOO_MANY_REQUESTS.value(),
				false);
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
	}

	@ExceptionHandler(VerificationTokenExpiredException.class)
	public  ResponseEntity<ExceptionResponse> handleVerificationTokenExpiredException(VerificationTokenExpiredException exception,WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.UNAUTHORIZED.value(),
				false);
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
	}

	@ExceptionHandler(InvalidVerificationTokenException.class)
	public  ResponseEntity<ExceptionResponse> handleInvalidVerificationTokenException(InvalidVerificationTokenException exception,WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.BAD_REQUEST.value(),
				false);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
	}

	@ExceptionHandler(EmailVerificationException.class)
	public  ResponseEntity<ExceptionResponse> handleEmailVerificationException(EmailVerificationException exception,WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.INTERNAL_SERVER_ERROR.value(),
				false);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	}

	@ExceptionHandler(UserAlreadyVerifiedException.class)
	public  ResponseEntity<ExceptionResponse> handleUserAlreadyVerifiedException(UserAlreadyVerifiedException exception,WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.OK.value(),
				false);
		return ResponseEntity.status(HttpStatus.OK).body(errorResponse);
	}

	@ExceptionHandler(EmailTooManyRequestException.class)
	public ResponseEntity<ExceptionResponse> handleEmailTooManyRequestException(EmailTooManyRequestException exception, WebRequest request){
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.TOO_MANY_REQUESTS.value(),
				false);
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
	}

	@ExceptionHandler(MissingServletRequestParameterException.class)
	public ResponseEntity<ExceptionResponse> handleMissingServletRequestParameterException(MissingServletRequestParameterException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.BAD_REQUEST.value(),
				false);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
	}

	@ExceptionHandler(ConstraintViolationException.class)
	public ResponseEntity<ExceptionResponse> handleConstraintViolationException(ConstraintViolationException exception, WebRequest request) {
		ExceptionResponse errorResponse = new ExceptionResponse( exception.getMessage(),
				LocalDateTime.now(),
				request.getDescription(false),
				HttpStatus.BAD_REQUEST.value(),
				false);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
	}

}
