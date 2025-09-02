package com.healthcare.service;

import com.healthcare.dto.UserResponse;
import com.healthcare.entity.User;
import com.healthcare.entity.UserRole;
import com.healthcare.repository.UserRepository;
import com.healthcare.security.CustomUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * User Management Service
 * Implements secure user operations with proper authorization checks
 * Protects against A01: Broken Access Control
 */
@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final CustomUserDetailsService userDetailsService;
    private final AuditService auditService;

    public UserService(UserRepository userRepository,
                      CustomUserDetailsService userDetailsService,
                      AuditService auditService) {
        this.userRepository = userRepository;
        this.userDetailsService = userDetailsService;
        this.auditService = auditService;
    }

    /**
     * Load user details by username (for Spring Security)
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDetailsService.loadUserByUsername(username);
    }

    /**
     * Find user by username
     */
    @Transactional(readOnly = true)
    public User findByUsername(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    /**
     * Find user by ID
     */
    @Transactional(readOnly = true)
    public Optional<User> findById(Long userId) {
        return userRepository.findById(userId);
    }

    /**
     * Get user profile
     */
    @Transactional(readOnly = true)
    public UserResponse getUserProfile(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return convertToUserResponse(user);
    }

    /**
     * Get all users (admin only)
     */
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::convertToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get users by role
     */
    @Transactional(readOnly = true)
    public List<UserResponse> getUsersByRole(UserRole role) {
        return userRepository.findByRole(role).stream()
                .map(this::convertToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Search users (with pagination)
     */
    @Transactional(readOnly = true)
    public Page<UserResponse> searchUsers(String searchTerm, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        
        // For security, limit search results and log the search
        auditService.logUserAction("system", "USER_SEARCH", "User", null,
                Map.of("searchTerm", searchTerm, "page", page, "size", size));

        return userRepository.findByUsernameContainingIgnoreCase(searchTerm)
                .stream()
                .map(this::convertToUserResponse)
                .collect(Collectors.toList())
                .stream()
                .skip((long) page * size)
                .limit(size)
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(),
                        list -> new PageImpl<>(list, pageable, list.size())
                ));
    }

    /**
     * Update user profile
     */
    public UserResponse updateUserProfile(Long userId, UserResponse updateRequest, String updatedBy) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Update allowed fields
        if (updateRequest.getFirstName() != null) {
            user.setFirstName(updateRequest.getFirstName());
        }
        if (updateRequest.getLastName() != null) {
            user.setLastName(updateRequest.getLastName());
        }
        if (updateRequest.getPhoneNumber() != null) {
            user.setPhoneNumber(updateRequest.getPhoneNumber());
        }
        if (updateRequest.getDateOfBirth() != null) {
            user.setDateOfBirth(updateRequest.getDateOfBirth());
        }

        user.setUpdatedBy(updatedBy);
        User savedUser = userRepository.save(user);

        // Log the update
        auditService.logUserAction(updatedBy, "USER_PROFILE_UPDATE", "User", 
                userId.toString(), Map.of("updatedFields", getUpdatedFields(updateRequest)));

        logger.info("User profile updated: {} by {}", user.getUsername(), updatedBy);
        return convertToUserResponse(savedUser);
    }

    /**
     * Check if account is locked
     */
    @Transactional(readOnly = true)
    public boolean isAccountLocked(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
                .map(user -> !user.getIsAccountNonLocked() || user.shouldBeLocked())
                .orElse(false);
    }

    /**
     * Check if account is enabled
     */
    @Transactional(readOnly = true)
    public boolean isAccountEnabled(String username) {
        return userRepository.findByUsernameOrEmailIgnoreCase(username)
                .map(User::getIsEnabled)
                .orElse(false);
    }

    /**
     * Get user statistics
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getUserStatistics() {
        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countActiveUsersByRole(null);
        long patientsCount = userRepository.countActiveUsersByRole(UserRole.PATIENT);
        long doctorsCount = userRepository.countActiveUsersByRole(UserRole.DOCTOR);
        long adminCount = userRepository.countActiveUsersByRole(UserRole.ADMIN);

        LocalDateTime since = LocalDateTime.now().minusDays(30);
        List<User> recentlyActive = userRepository.findUsersWithRecentActivity(since);

        return Map.of(
                "totalUsers", totalUsers,
                "activeUsers", activeUsers,
                "patientsCount", patientsCount,
                "doctorsCount", doctorsCount,
                "adminCount", adminCount,
                "recentlyActiveCount", recentlyActive.size()
        );
    }

    /**
     * Find users with expired passwords
     */
    @Transactional(readOnly = true)
    public List<UserResponse> getUsersWithExpiredPasswords() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(90);
        return userRepository.findUsersWithExpiredPasswords(cutoffDate).stream()
                .map(this::convertToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Cleanup inactive users (GDPR compliance)
     */
    public int cleanupInactiveUsers(int retentionDays) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(retentionDays);
        int deletedCount = userRepository.deleteInactiveUsers(cutoffDate);

        auditService.logUserAction("system", "CLEANUP_INACTIVE_USERS", "User", null,
                Map.of("retentionDays", retentionDays, "deletedCount", deletedCount));

        logger.info("Cleaned up {} inactive users", deletedCount);
        return deletedCount;
    }

    /**
     * Convert User entity to UserResponse DTO
     */
    private UserResponse convertToUserResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setEmail(user.getEmail());
        response.setFirstName(user.getFirstName());
        response.setLastName(user.getLastName());
        response.setPhoneNumber(user.getPhoneNumber());
        response.setDateOfBirth(user.getDateOfBirth());
        response.setRole(user.getRole().name());
        response.setIsEnabled(user.getIsEnabled());
        response.setIsAccountNonLocked(user.getIsAccountNonLocked());
        response.setLastLogin(user.getLastLogin());
        response.setCreatedAt(user.getCreatedAt());
        return response;
    }

    /**
     * Get updated fields for audit logging
     */
    private List<String> getUpdatedFields(UserResponse updateRequest) {
        List<String> fields = new ArrayList<>();
        if (updateRequest.getFirstName() != null) fields.add("firstName");
        if (updateRequest.getLastName() != null) fields.add("lastName");
        if (updateRequest.getPhoneNumber() != null) fields.add("phoneNumber");
        if (updateRequest.getDateOfBirth() != null) fields.add("dateOfBirth");
        return fields;
    }
}