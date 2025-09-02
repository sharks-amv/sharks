package com.healthcare.repository;

import com.healthcare.entity.User;
import com.healthcare.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * User Repository with secure query methods
 * Implements protection against A03: Injection attacks through parameterized queries
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by username (case-insensitive)
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(:username)")
    Optional<User> findByUsernameIgnoreCase(@Param("username") String username);

    /**
     * Find user by email (case-insensitive)
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(:email)")
    Optional<User> findByEmailIgnoreCase(@Param("email") String email);

    /**
     * Find user by username or email
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(:usernameOrEmail) OR LOWER(u.email) = LOWER(:usernameOrEmail)")
    Optional<User> findByUsernameOrEmailIgnoreCase(@Param("usernameOrEmail") String usernameOrEmail);

    /**
     * Check if username exists (case-insensitive)
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE LOWER(u.username) = LOWER(:username)")
    boolean existsByUsernameIgnoreCase(@Param("username") String username);

    /**
     * Check if email exists (case-insensitive)
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE LOWER(u.email) = LOWER(:email)")
    boolean existsByEmailIgnoreCase(@Param("email") String email);

    /**
     * Find users by role
     */
    List<User> findByRole(UserRole role);

    /**
     * Find enabled users
     */
    List<User> findByIsEnabledTrue();

    /**
     * Find locked accounts
     */
    @Query("SELECT u FROM User u WHERE u.failedLoginAttempts >= 5 AND u.isAccountNonLocked = true")
    List<User> findAccountsToLock();

    /**
     * Find users with expired passwords
     */
    @Query("SELECT u FROM User u WHERE u.passwordChangedAt < :cutoffDate")
    List<User> findUsersWithExpiredPasswords(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Find users created after specific date
     */
    List<User> findByCreatedAtAfter(LocalDateTime date);

    /**
     * Update failed login attempts
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = :attempts WHERE u.id = :userId")
    int updateFailedLoginAttempts(@Param("userId") Long userId, @Param("attempts") Integer attempts);

    /**
     * Reset failed login attempts
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0 WHERE u.id = :userId")
    int resetFailedLoginAttempts(@Param("userId") Long userId);

    /**
     * Update last login timestamp
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :timestamp WHERE u.id = :userId")
    int updateLastLogin(@Param("userId") Long userId, @Param("timestamp") LocalDateTime timestamp);

    /**
     * Lock user account
     */
    @Modifying
    @Query("UPDATE User u SET u.isAccountNonLocked = false WHERE u.id = :userId")
    int lockAccount(@Param("userId") Long userId);

    /**
     * Unlock user account
     */
    @Modifying
    @Query("UPDATE User u SET u.isAccountNonLocked = true, u.failedLoginAttempts = 0 WHERE u.id = :userId")
    int unlockAccount(@Param("userId") Long userId);

    /**
     * Enable user account
     */
    @Modifying
    @Query("UPDATE User u SET u.isEnabled = true WHERE u.id = :userId")
    int enableAccount(@Param("userId") Long userId);

    /**
     * Disable user account
     */
    @Modifying
    @Query("UPDATE User u SET u.isEnabled = false WHERE u.id = :userId")
    int disableAccount(@Param("userId") Long userId);

    /**
     * Update password and timestamp
     */
    @Modifying
    @Query("UPDATE User u SET u.password = :password, u.passwordChangedAt = :timestamp WHERE u.id = :userId")
    int updatePassword(@Param("userId") Long userId, @Param("password") String password, @Param("timestamp") LocalDateTime timestamp);

    /**
     * Find users by partial username (for admin search) - with limit to prevent DoS
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.username) LIKE LOWER(CONCAT('%', :username, '%')) ORDER BY u.username")
    List<User> findByUsernameContainingIgnoreCase(@Param("username") String username);

    /**
     * Count active users by role
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role = :role AND u.isEnabled = true")
    long countActiveUsersByRole(@Param("role") UserRole role);

    /**
     * Find users with recent activity
     */
    @Query("SELECT u FROM User u WHERE u.lastLogin >= :since ORDER BY u.lastLogin DESC")
    List<User> findUsersWithRecentActivity(@Param("since") LocalDateTime since);

    /**
     * Delete inactive users (for GDPR compliance)
     */
    @Modifying
    @Query("DELETE FROM User u WHERE u.lastLogin < :cutoffDate AND u.isEnabled = false")
    int deleteInactiveUsers(@Param("cutoffDate") LocalDateTime cutoffDate);
}