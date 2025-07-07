package com.mhs.authService.exception.model;

import java.time.LocalDateTime;

public record ExceptionResponse (String message,
                                LocalDateTime timestamp,
                                String path,
                                int status,
                                boolean success){}

