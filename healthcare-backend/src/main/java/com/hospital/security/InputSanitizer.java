package com.healthcare.security;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.stereotype.Service;
import java.util.regex.Pattern;

/**
 * Input Sanitization Service
 * Implements protection against A03: Injection attacks (XSS, SQL Injection, etc.)
 */
@Service
public class InputSanitizer {

    private final PolicyFactory htmlSanitizer;
    private final Pattern sqlInjectionPattern;
    private final Pattern xssPattern;
    private final Pattern pathTraversalPattern;

    public InputSanitizer() {
        // Configure HTML sanitizer policy
        this.htmlSanitizer = new HtmlPolicyBuilder()
                .allowElements("p", "br", "strong", "em", "ul", "ol", "li")
                .allowAttributes("class").onElements("p", "div")
                .toFactory();

        // Compile regex patterns for security checks
        this.sqlInjectionPattern = Pattern.compile(
            "(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|vbscript)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
        );

        this.xssPattern = Pattern.compile(
            "(?i)(<script|javascript:|vbscript:|onload|onerror|onclick|onmouseover)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
        );

        this.pathTraversalPattern = Pattern.compile(
            "(\\.\\./|\\.\\\\|%2e%2e%2f|%2e%2e%5c)",
            Pattern.CASE_INSENSITIVE
        );
    }

    /**
     * Sanitize HTML content to prevent XSS attacks
     */
    public String sanitizeHtml(String input) {
        if (input == null) {
            return null;
        }
        return htmlSanitizer.sanitize(input);
    }

    /**
     * Sanitize general text input
     */
    public String sanitizeText(String input) {
        if (input == null) {
            return null;
        }
        
        // Remove null characters
        String sanitized = input.replace("\0", "");
        
        // Normalize whitespace
        sanitized = sanitized.replaceAll("\\s+", " ").trim();
        
        // Remove control characters except tabs, newlines, and carriage returns
        sanitized = sanitized.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
        
        return sanitized;
    }

    /**
     * Validate input for potential SQL injection attempts
     */
    public boolean containsSqlInjection(String input) {
        if (input == null) {
            return false;
        }
        return sqlInjectionPattern.matcher(input).find();
    }

    /**
     * Validate input for potential XSS attempts
     */
    public boolean containsXss(String input) {
        if (input == null) {
            return false;
        }
        return xssPattern.matcher(input).find();
    }

    /**
     * Validate input for path traversal attempts
     */
    public boolean containsPathTraversal(String input) {
        if (input == null) {
            return false;
        }
        return pathTraversalPattern.matcher(input).find();
    }

    /**
     * Comprehensive input validation
     */
    public ValidationResult validateInput(String input) {
        if (input == null) {
            return new ValidationResult(true, "Input is null");
        }

        if (containsSqlInjection(input)) {
            return new ValidationResult(false, "Potential SQL injection detected");
        }

        if (containsXss(input)) {
            return new ValidationResult(false, "Potential XSS attack detected");
        }

        if (containsPathTraversal(input)) {
            return new ValidationResult(false, "Path traversal attempt detected");
        }

        return new ValidationResult(true, "Input is valid");
    }

    /**
     * Sanitize filename for secure file operations
     */
    public String sanitizeFilename(String filename) {
        if (filename == null) {
            return null;
        }

        // Remove path separators and special characters
        String sanitized = filename.replaceAll("[/\\\\:*?\"<>|]", "");
        
        // Remove leading/trailing dots and spaces
        sanitized = sanitized.replaceAll("^[.\\s]+|[.\\s]+$", "");
        
        // Limit length
        if (sanitized.length() > 255) {
            sanitized = sanitized.substring(0, 255);
        }
        
        // Prevent reserved names on Windows
        String[] reservedNames = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};
        for (String reserved : reservedNames) {
            if (sanitized.equalsIgnoreCase(reserved)) {
                sanitized = "file_" + sanitized;
                break;
            }
        }

        return sanitized.isEmpty() ? "unnamed_file" : sanitized;
    }

    /**
     * Validation result class
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String message;

        public ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public boolean isValid() {
            return valid;
        }

        public String getMessage() {
            return message;
        }
    }
}