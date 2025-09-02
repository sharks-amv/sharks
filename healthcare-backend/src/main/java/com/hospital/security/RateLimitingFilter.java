package com.healthcare.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate Limiting Filter to prevent abuse and DDoS attacks
 * Implements protection against A06: Vulnerable and Outdated Components
 * and helps prevent brute force attacks (A07: Identification and Authentication Failures)
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);
    
    @Value("${app.rate-limit.requests-per-minute:100}")
    private int requestsPerMinute;
    
    @Value("${app.rate-limit.burst-capacity:200}")
    private int burstCapacity;
    
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String clientIdentifier = getClientIdentifier(request);
        Bucket bucket = getBucket(clientIdentifier);
        
        if (bucket.tryConsume(1)) {
            // Request allowed
            filterChain.doFilter(request, response);
        } else {
            // Rate limit exceeded
            logger.warn("Rate limit exceeded for client: {}", clientIdentifier);
            
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Too many requests\",\"message\":\"Rate limit exceeded\"}");
            response.getWriter().flush();
        }
    }

    /**
     * Get or create a bucket for the client
     */
    private Bucket getBucket(String clientIdentifier) {
        return buckets.computeIfAbsent(clientIdentifier, key -> {
            // Create bandwidth configuration
            Bandwidth bandwidth = Bandwidth.classic(burstCapacity, Refill.intervally(requestsPerMinute, Duration.ofMinutes(1)));
            return Bucket.builder()
                    .addLimit(bandwidth)
                    .build();
        });
    }

    /**
     * Get client identifier (IP address or authenticated user)
     */
    private String getClientIdentifier(HttpServletRequest request) {
        // Check for authenticated user first
        String username = request.getRemoteUser();
        if (username != null) {
            return "user:" + username;
        }
        
        // Fall back to IP address
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return "ip:" + xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return "ip:" + xRealIP;
        }
        
        return "ip:" + request.getRemoteAddr();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        
        // Apply more lenient rate limiting to health checks
        return path.equals("/api/v1/actuator/health");
    }
}