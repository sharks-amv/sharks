package com.healthcare.security;

import com.healthcare.entity.User;
import com.healthcare.repository.UserRepository;
import com.healthcare.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Collections;

/**
 * Custom User Details Service
 * Implements secure user loading for authentication
 * Protects against A07: Identification and Authentication Failures
 */
@Service
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    private final UserRepository userRepository;
    private final AuditService auditService;

    public CustomUserDetailsService(UserRepository userRepository, AuditService auditService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        logger.debug("Loading user by username/email: {}", usernameOrEmail);

        User user = userRepository.findByUsernameOrEmailIgnoreCase(usernameOrEmail)
                .orElseThrow(() -> {
                    logger.warn("User not found with username/email: {}", usernameOrEmail);
                    auditService.logSecurityEvent(usernameOrEmail, "USER_NOT_FOUND", "N/A", 
                        "Attempted to load non-existent user");
                    return new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail);
                });

        return createUserPrincipal(user);
    }

    /**
     * Load user by ID (used for JWT token validation)
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

        return createUserPrincipal(user);
    }

    /**
     * Create Spring Security UserDetails from our User entity
     */
    private UserDetails createUserPrincipal(User user) {
        Collection<? extends GrantedAuthority> authorities = getUserAuthorities(user);

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(authorities)
                .accountExpired(!user.getIsAccountNonExpired())
                .accountLocked(!user.getIsAccountNonLocked())
                .credentialsExpired(!user.getIsCredentialsNonExpired())
                .disabled(!user.getIsEnabled())
                .build();
    }

    /**
     * Get user authorities (roles and permissions)
     */
    private Collection<? extends GrantedAuthority> getUserAuthorities(User user) {
        // Primary role authority
        String roleAuthority = "ROLE_" + user.getRole().name();
        return Collections.singletonList(new SimpleGrantedAuthority(roleAuthority));
    }

    /**
     * Check if user account should be locked due to failed attempts
     */
    public boolean shouldLockAccount(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
                .map(User::shouldBeLocked)
                .orElse(false);
    }

    /**
     * Check if password is expired
     */
    public boolean isPasswordExpired(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
                .map(User::isPasswordExpired)
                .orElse(false);
    }
}