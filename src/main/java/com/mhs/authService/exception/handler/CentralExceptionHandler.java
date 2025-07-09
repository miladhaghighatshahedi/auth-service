package com.mhs.authService.exception.handler;

import com.mhs.authService.exception.error.*;
import com.mhs.authService.exception.model.ExceptionResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import java.time.LocalDateTime;

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

}
