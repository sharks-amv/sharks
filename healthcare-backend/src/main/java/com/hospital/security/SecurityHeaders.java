package com.healthcare.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;

/**
 * Custom security headers writer
 * Implements protection against A05: Security Misconfiguration
 */
public class SecurityHeaders implements HeaderWriter {

    @Override
    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        // Content Security Policy - prevents XSS attacks (A03: Injection)
        response.setHeader("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' https://fonts.gstatic.com; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'");

        // X-Content-Type-Options - prevents MIME type sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");

        // X-Frame-Options - prevents clickjacking
        response.setHeader("X-Frame-Options", "DENY");

        // X-XSS-Protection - enables XSS filtering
        response.setHeader("X-XSS-Protection", "1; mode=block");

        // Referrer Policy - controls referrer information
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Permissions Policy - controls browser features
        response.setHeader("Permissions-Policy", 
            "geolocation=(), " +
            "microphone=(), " +
            "camera=(), " +
            "midi=(), " +
            "encrypted-media=(), " +
            "autoplay=()");

        // Cache Control for sensitive data
        if (request.getRequestURI().contains("/api/")) {
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Expires", "0");
        }

        // Server header removal (security through obscurity)
        response.setHeader("Server", "Healthcare-API");

        // Additional security headers
        response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
        response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    }
}