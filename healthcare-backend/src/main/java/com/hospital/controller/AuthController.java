package com.healthcare.controller;

import com.healthcare.dto.AuthRequest;
import com.healthcare.dto.AuthResponse;
import com.healthcare.dto.RegisterRequest;
import com.healthcare.entity.User;
import com.healthcare.entity.UserRole;
import com.healthcare.security.InputSanitizer;
import com.healthcare.security.JwtUtil;
import com.healthcare.service.AuthService;
import com.healthcare.service.AuditService;
import com.healthcare.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Authentication Controller
 * Implements secure authentication endpoints
 * Protects against A07: Identification and Authentication Failures
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final AuthService authService;
    private final AuditService auditService;
    private final InputSanitizer inputSanitizer;

    public AuthController(AuthenticationManager authenticationManager,
                         JwtUtil jwtUtil,
                         UserService userService,
                         AuthService authService,
                         AuditService auditService,
                         InputSanitizer inputSanitizer) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.authService = authService;
        this.auditService = auditService;
        this.inputSanitizer = inputSanitizer;
    }

    /**
     * User login endpoint
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest authRequest, 
                                  HttpServletRequest request) {
        
        String clientIp = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        // Sanitize inputs
        String username = inputSanitizer.sanitizeText(authRequest.getUsername());
        String password = authRequest.getPassword(); // Don't sanitize password

        // Validate input
        InputSanitizer.ValidationResult validation = inputSanitizer.validateInput(username);
        if (!validation.isValid()) {
            auditService.logSecurityEvent(username, "INVALID_INPUT", clientIp, validation.getMessage());
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Invalid input", "message", "Invalid characters detected"));
        }

        try {
            // Check if account is locked
            if (userService.isAccountLocked(username)) {
                auditService.logLoginAttempt(username, clientIp, false, "Account locked");
                return ResponseEntity.status(HttpStatus.LOCKED)
                    .body(Map.of("error", "Account locked", "message", "Account is locked due to multiple failed login attempts"));
            }

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername());

            // Generate tokens
            String accessToken = jwtUtil.generateToken(userDetails);
            String refreshToken = jwtUtil.generateRefreshToken(userDetails);

            // Update login tracking
            authService.handleSuccessfulLogin(user, clientIp);

            // Log successful login
            auditService.logLoginAttempt(username, clientIp, true, null);

            AuthResponse response = new AuthResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtUtil.getTokenRemainingTime(accessToken),
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                user.getFullName()
            );

            return ResponseEntity.ok(response);

        } catch (BadCredentialsException ex) {
            // Handle failed login attempt
            authService.handleFailedLogin(username, clientIp);
            auditService.logLoginAttempt(username, clientIp, false, "Bad credentials");
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Authentication failed", "message", "Invalid username or password"));

        } catch (LockedException ex) {
            auditService.logLoginAttempt(username, clientIp, false, "Account locked");
            return ResponseEntity.status(HttpStatus.LOCKED)
                .body(Map.of("error", "Account locked", "message", "Your account has been locked"));

        } catch (DisabledException ex) {
            auditService.logLoginAttempt(username, clientIp, false, "Account disabled");
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Account disabled", "message", "Your account has been disabled"));

        } catch (Exception ex) {
            logger.error("Login error for user: {}", username, ex);
            auditService.logSecurityEvent(username, "LOGIN_ERROR", clientIp, ex.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Login failed", "message", "An error occurred during login"));
        }
    }

    /**
     * User registration endpoint
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest,
                                     HttpServletRequest request) {
        
        String clientIp = getClientIpAddress(request);

        try {
            // Sanitize inputs
            registerRequest.setUsername(inputSanitizer.sanitizeText(registerRequest.getUsername()));
            registerRequest.setEmail(inputSanitizer.sanitizeText(registerRequest.getEmail()));
            registerRequest.setFirstName(inputSanitizer.sanitizeText(registerRequest.getFirstName()));
            registerRequest.setLastName(inputSanitizer.sanitizeText(registerRequest.getLastName()));

            // Validate inputs
            for (String input : new String[]{registerRequest.getUsername(), registerRequest.getEmail(), 
                                           registerRequest.getFirstName(), registerRequest.getLastName()}) {
                InputSanitizer.ValidationResult validation = inputSanitizer.validateInput(input);
                if (!validation.isValid()) {
                    return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid input", "message", validation.getMessage()));
                }
            }

            // Create user
            User user = authService.createUser(registerRequest);
            
            // Log registration
            auditService.logUserAction(user.getUsername(), "USER_REGISTRATION", "User", 
                user.getId().toString(), Map.of("email", user.getEmail(), "role", user.getRole().name()));

            return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully", "userId", user.getId()));

        } catch (IllegalArgumentException ex) {
            auditService.logSecurityEvent("anonymous", "REGISTRATION_FAILED", clientIp, ex.getMessage());
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Registration failed", "message", ex.getMessage()));

        } catch (Exception ex) {
            logger.error("Registration error", ex);
            auditService.logSecurityEvent("anonymous", "REGISTRATION_ERROR", clientIp, ex.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Registration failed", "message", "An error occurred during registration"));
        }
    }

    /**
     * Refresh token endpoint
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request,
                                         HttpServletRequest httpRequest) {
        
        String refreshToken = request.get("refreshToken");
        String clientIp = getClientIpAddress(httpRequest);

        try {
            if (!jwtUtil.validateToken(refreshToken) || !jwtUtil.isRefreshToken(refreshToken)) {
                auditService.logSecurityEvent("unknown", "INVALID_REFRESH_TOKEN", clientIp, "Invalid refresh token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token", "message", "Invalid refresh token"));
            }

            String username = jwtUtil.getUsernameFromToken(refreshToken);
            UserDetails userDetails = userService.loadUserByUsername(username);
            
            String newAccessToken = jwtUtil.generateToken(userDetails);
            String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);

            auditService.logSecurityEvent(username, "TOKEN_REFRESH", clientIp, "Access token refreshed");

            return ResponseEntity.ok(Map.of(
                "accessToken", newAccessToken,
                "refreshToken", newRefreshToken,
                "expiresIn", jwtUtil.getTokenRemainingTime(newAccessToken)
            ));

        } catch (Exception ex) {
            logger.error("Token refresh error", ex);
            auditService.logSecurityEvent("unknown", "TOKEN_REFRESH_ERROR", clientIp, ex.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Token refresh failed", "message", "Unable to refresh token"));
        }
    }

    /**
     * Logout endpoint
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        
        String clientIp = getClientIpAddress(request);
        String username = request.getRemoteUser();

        try {
            // In a complete implementation, you would invalidate the token
            // by adding it to a blacklist or removing from a whitelist

            auditService.logLogout(username != null ? username : "unknown", clientIp);

            return ResponseEntity.ok(Map.of("message", "Logged out successfully"));

        } catch (Exception ex) {
            logger.error("Logout error", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Logout failed", "message", "An error occurred during logout"));
        }
    }

    /**
     * Get current user profile
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        
        try {
            String username = request.getRemoteUser();
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Unauthorized", "message", "User not authenticated"));
            }

            User user = userService.findByUsername(username);
            
            return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "fullName", user.getFullName(),
                "role", user.getRole().name(),
                "enabled", user.getIsEnabled(),
                "accountNonLocked", user.getIsAccountNonLocked(),
                "lastLogin", user.getLastLogin()
            ));

        } catch (Exception ex) {
            logger.error("Error getting current user", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Profile fetch failed", "message", "Unable to fetch user profile"));
        }
    }

    /**
     * Extract client IP address from request
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}