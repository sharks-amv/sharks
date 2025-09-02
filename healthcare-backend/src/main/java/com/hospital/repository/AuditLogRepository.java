package com.healthcare.repository;

import com.healthcare.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Audit Log Repository
 * Implements A09: Security Logging and Monitoring Failures protection
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    /**
     * Find audit logs by username
     */
    List<AuditLog> findByUsernameOrderByTimestampDesc(String username);

    /**
     * Find audit logs by action
     */
    List<AuditLog> findByActionOrderByTimestampDesc(String action);

    /**
     * Find audit logs by resource
     */
    List<AuditLog> findByResourceOrderByTimestampDesc(String resource);

    /**
     * Find audit logs within date range
     */
    @Query("SELECT a FROM AuditLog a WHERE a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    List<AuditLog> findByTimestampBetween(@Param("startDate") LocalDateTime startDate, 
                                         @Param("endDate") LocalDateTime endDate);

    /**
     * Find audit logs by user and date range
     */
    @Query("SELECT a FROM AuditLog a WHERE a.username = :username AND a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    List<AuditLog> findByUsernameAndTimestampBetween(@Param("username") String username,
                                                    @Param("startDate") LocalDateTime startDate,
                                                    @Param("endDate") LocalDateTime endDate);

    /**
     * Find recent audit logs for a user
     */
    @Query("SELECT a FROM AuditLog a WHERE a.username = :username AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentByUsername(@Param("username") String username, 
                                       @Param("since") LocalDateTime since);

    /**
     * Count audit logs by action in time period
     */
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.action = :action AND a.timestamp >= :since")
    long countByActionSince(@Param("action") String action, @Param("since") LocalDateTime since);

    /**
     * Find data access logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.action = 'DATA_ACCESS' AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findDataAccessLogsSince(@Param("since") LocalDateTime since);

    /**
     * Find sensitive operations
     */
    @Query("SELECT a FROM AuditLog a WHERE a.action IN ('DATA_EXPORT', 'USER_DELETE', 'ROLE_CHANGE') ORDER BY a.timestamp DESC")
    List<AuditLog> findSensitiveOperations();

    /**
     * Find logs by IP address
     */
    List<AuditLog> findByIpAddressOrderByTimestampDesc(String ipAddress);

    /**
     * Delete old audit logs (for retention policy)
     */
    @Modifying
    @Query("DELETE FROM AuditLog a WHERE a.timestamp < :cutoffDate")
    int deleteByTimestampBefore(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Count logs by username in time period
     */
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.username = :username AND a.timestamp >= :since")
    long countByUsernameSince(@Param("username") String username, @Param("since") LocalDateTime since);

    /**
     * Find suspicious activity patterns
     */
    @Query("SELECT a FROM AuditLog a WHERE a.severity = 'HIGH' AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<AuditLog> findHighSeverityLogsSince(@Param("since") LocalDateTime since);
}