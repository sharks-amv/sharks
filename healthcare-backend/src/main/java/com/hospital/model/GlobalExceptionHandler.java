package com.healthcare.exception;

import com.healthcare.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    private final AuditService auditService;

    public GlobalExceptionHandler(AuditService auditService) {
        this.auditService = auditService;
    }

    /**
     * ⭐ IMPROVEMENT: Using a dedicated, immutable record for error responses.
     * This is type-safe and cleaner than using a Map.
     */
    private record ErrorResponse(LocalDateTime timestamp, int status, String error, String message, String path, Map<String, String> validationErrors) {
        // Constructor for general errors without validation details
        ErrorResponse(HttpStatus status, String error, String message, String path) {
            this(LocalDateTime.now(), status.value(), error, message, path, null);
        }
        // Constructor for validation errors
        ErrorResponse(HttpStatus status, String message, String path, Map<String, String> validationErrors) {
            this(LocalDateTime.now(), status.value(), "Validation Failed", message, path, validationErrors);
        }
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        auditService.logSecurityEvent(
            getUsername(), 
            "VALIDATION_FAILURE", 
            getClientIp(request),
            "Validation failed on " + errors.size() + " fields."
        );
        
        ErrorResponse response = new ErrorResponse(HttpStatus.BAD_REQUEST, "Input validation failed", request.getRequestURI(), errors);
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex, HttpServletRequest request) {
        auditService.logSecurityEvent(
            "anonymous", // ✅ FIX: Username is unknown during a failed login attempt
            "BAD_CREDENTIALS", 
            getClientIp(request),
            "Invalid username or password provided."
        );
        
        ErrorResponse response = new ErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid Credentials", "Username or password is incorrect", request.getRequestURI());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest request) {
        // ✅ FIX & IMPROVEMENT: Using a consistent audit method
        auditService.logSecurityEvent(
            getUsername(), 
            "ACCESS_DENIED", 
            getClientIp(request),
            "User attempted to access a forbidden resource: " + request.getRequestURI()
        );
        
        ErrorResponse response = new ErrorResponse(HttpStatus.FORBIDDEN, "Access Denied", "You do not have permission to access this resource", request.getRequestURI());
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex, HttpServletRequest request) {
        logger.warn("Illegal argument exception for request {}: {}", request.getRequestURI(), ex.getMessage());
        
        // ✅ FIX: Added missing audit log for potentially malicious input
        auditService.logSecurityEvent(
            getUsername(),
            "ILLEGAL_ARGUMENT",
            getClientIp(request),
            "Illegal argument: " + ex.getMessage()
        );
        
        ErrorResponse response = new ErrorResponse(HttpStatus.BAD_REQUEST, "Bad Request", "Invalid request parameters provided", request.getRequestURI());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * ⭐ IMPROVEMENT: A single catch-all handler for all other exceptions.
     * This reduces code duplication and ensures all unexpected errors are logged and audited.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAllUncaughtExceptions(Exception ex, HttpServletRequest request) {
        logger.error("An unexpected error occurred for request " + request.getRequestURI(), ex);
        
        // ✅ FIX: Added audit log for all unexpected server errors
        auditService.logSecurityEvent(
            getUsername(), 
            "UNCAUGHT_EXCEPTION", 
            getClientIp(request),
            ex.getClass().getSimpleName() + " at " + request.getRequestURI()
        );
        
        ErrorResponse response = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred. Please try again later.", request.getRequestURI());
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * ✅ FIX: Rewritten to use SecurityContextHolder for reliable username retrieval.
     */
    private String getUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            return "anonymous";
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }
        return principal.toString();
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}