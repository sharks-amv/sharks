package com.healthcare.service;

import com.healthcare.dto.RegisterRequest;
import com.healthcare.entity.User;
import com.healthcare.entity.UserRole;
import com.healthcare.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Authentication Service
 * Handles user authentication and registration with security measures
 * Implements A07: Identification and Authentication Failures protection
 */
@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public AuthService(UserRepository userRepository, 
                      PasswordEncoder passwordEncoder,
                      AuditService auditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    /**
     * Create new user account
     */
    public User createUser(RegisterRequest registerRequest) {
        logger.info("Creating new user account: {}", registerRequest.getUsername());

        // Check if username already exists
        if (userRepository.existsByUsernameIgnoreCase(registerRequest.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Check if email already exists
        if (userRepository.existsByEmailIgnoreCase(registerRequest.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        // Create new user entity
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setPhoneNumber(registerRequest.getPhoneNumber());
        user.setDateOfBirth(registerRequest.getDateOfBirth());
        user.setRole(UserRole.PATIENT); // Default role for registration
        user.setIsEnabled(true);
        user.setIsAccountNonExpired(true);
        user.setIsAccountNonLocked(true);
        user.setIsCredentialsNonExpired(true);
        user.setFailedLoginAttempts(0);
        user.setTwoFactorEnabled(false);

        // Save user
        User savedUser = userRepository.save(user);
        logger.info("User created successfully: {}", savedUser.getUsername());

        return savedUser;
    }

    /**
     * Handle successful login
     */
    public void handleSuccessfulLogin(User user, String ipAddress) {
        // Reset failed login attempts
        user.resetFailedLoginAttempts();
        user.setLastLogin(LocalDateTime.now());
        
        userRepository.save(user);
        
        logger.info("Successful login for user: {} from IP: {}", user.getUsername(), ipAddress);
    }

    /**
     * Handle failed login attempt
     */
    public void handleFailedLogin(String username, String ipAddress) {
        userRepository.findByUsernameOrEmailIgnoreCase(username)
            .ifPresent(user -> {
                user.incrementFailedLoginAttempts();
                
                // Lock account if too many failed attempts
                if (user.shouldBeLocked()) {
                    user.setIsAccountNonLocked(false);
                    logger.warn("Account locked due to failed login attempts: {}", username);
                    
                    auditService.logSecurityEvent(username, "ACCOUNT_LOCKED", ipAddress,
                        "Account locked after " + user.getFailedLoginAttempts() + " failed attempts");
                }
                
                userRepository.save(user);
            });
        
        logger.warn("Failed login attempt for user: {} from IP: {}", username, ipAddress);
    }

    /**
     * Unlock user account
     */
    public boolean unlockAccount(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
            .map(user -> {
                user.setIsAccountNonLocked(true);
                user.resetFailedLoginAttempts();
                userRepository.save(user);
                
                logger.info("Account unlocked: {}", username);
                return true;
            })
            .orElse(false);
    }

    /**
     * Change user password
     */
    public boolean changePassword(String username, String oldPassword, String newPassword) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
            .map(user -> {
                // Verify old password
                if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
                    auditService.logSecurityEvent(username, "PASSWORD_CHANGE_FAILED", "N/A",
                        "Old password verification failed");
                    return false;
                }
                
                // Check password reuse (in production, you'd check against password history)
                if (passwordEncoder.matches(newPassword, user.getPassword())) {
                    throw new IllegalArgumentException("New password must be different from current password");
                }
                
                // Update password
                user.setPassword(passwordEncoder.encode(newPassword));
                user.setPasswordChangedAt(LocalDateTime.now());
                user.setIsCredentialsNonExpired(true);
                
                userRepository.save(user);
                
                auditService.logPasswordChange(username, "N/A", true);
                logger.info("Password changed successfully for user: {}", username);
                
                return true;
            })
            .orElse(false);
    }

    /**
     * Reset password (admin function)
     */
    public boolean resetPassword(String username, String newPassword) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
            .map(user -> {
                user.setPassword(passwordEncoder.encode(newPassword));
                user.setPasswordChangedAt(LocalDateTime.now());
                user.setIsCredentialsNonExpired(false); // Force password change on next login
                
                userRepository.save(user);
                
                auditService.logSecurityEvent(username, "PASSWORD_RESET", "N/A",
                    "Password reset by administrator");
                logger.info("Password reset for user: {}", username);
                
                return true;
            })
            .orElse(false);
    }

    /**
     * Enable user account
     */
    public boolean enableAccount(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
            .map(user -> {
                user.setIsEnabled(true);
                userRepository.save(user);
                
                auditService.logSecurityEvent(username, "ACCOUNT_ENABLED", "N/A",
                    "Account enabled by administrator");
                logger.info("Account enabled: {}", username);
                
                return true;
            })
            .orElse(false);
    }

    /**
     * Disable user account
     */
    public boolean disableAccount(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
            .map(user -> {
                user.setIsEnabled(false);
                userRepository.save(user);
                
                auditService.logSecurityEvent(username, "ACCOUNT_DISABLED", "N/A",
                    "Account disabled by administrator");
                logger.info("Account disabled: {}", username);
                
                return true;
            })
            .orElse(false);
    }

    /**
     * Validate password strength
     */
    public boolean isPasswordStrong(String password) {
        // Password must be at least 12 characters long
        if (password.length() < 12) {
            return false;
        }
        
        // Check for required character types
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch -> "!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(ch) >= 0);
        
        return hasLower && hasUpper && hasDigit && hasSpecial;
    }

    /**
     * Check for common passwords (basic implementation)
     */
    public boolean isCommonPassword(String password) {
        String[] commonPasswords = {
            "password123", "123456789", "qwerty123", "admin123", "letmein123",
            "welcome123", "password1234", "123456abc", "qwerty1234"
        };
        
        String lowerPassword = password.toLowerCase();
        for (String common : commonPasswords) {
            if (lowerPassword.contains(common)) {
                return true;
            }
        }
        
        return false;
    }
}