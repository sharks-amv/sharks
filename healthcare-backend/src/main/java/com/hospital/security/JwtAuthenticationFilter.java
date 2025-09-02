package com.healthcare.security;

import com.healthcare.service.AuditService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication Filter
 * Implements secure token validation to prevent A07: Identification and Authentication Failures
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_NAME = "Authorization";

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final AuditService auditService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, 
                                 CustomUserDetailsService userDetailsService,
                                 AuditService auditService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.auditService = auditService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = getJwtFromRequest(request);
            
            if (StringUtils.hasText(jwt) && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.getUsernameFromToken(jwt);
                
                // Load user details
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                if (jwtUtil.validateToken(jwt, userDetails)) {
                    // Create authentication token
                    UsernamePasswordAuthenticationToken authentication = 
                        new UsernamePasswordAuthenticationToken(
                            userDetails, 
                            null, 
                            userDetails.getAuthorities()
                        );
                    
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    
                    // Log successful authentication for audit
                    auditService.logSecurityEvent(
                        username, 
                        "JWT_AUTH_SUCCESS", 
                        request.getRemoteAddr(),
                        request.getHeader("User-Agent")
                    );
                }
            }
        } catch (JwtException ex) {
            logger.error("Cannot set user authentication: {}", ex.getMessage());
            
            // Log failed authentication attempt
            auditService.logSecurityEvent(
                "unknown", 
                "JWT_AUTH_FAILURE", 
                request.getRemoteAddr(),
                "Invalid JWT token: " + ex.getMessage()
            );
        } catch (Exception ex) {
            logger.error("Cannot set user authentication", ex);
        }
        
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from request header
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_NAME);
        
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        
        // Skip JWT validation for public endpoints
        return path.startsWith("/api/v1/auth/") ||
               path.startsWith("/api/v1/public/") ||
               path.equals("/api/v1/actuator/health") ||
               path.startsWith("/api/v1/swagger-ui/") ||
               path.startsWith("/api/v1/v3/api-docs/");
    }
}