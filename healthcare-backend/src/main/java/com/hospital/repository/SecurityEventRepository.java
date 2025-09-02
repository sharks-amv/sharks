package com.healthcare.repository;

import com.healthcare.entity.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Security Event Repository
 * Implements A09: Security Logging and Monitoring Failures protection
 */
@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    /**
     * Find security events by username
     */
    List<SecurityEvent> findByUsernameOrderByTimestampDesc(String username);

    /**
     * Find security events by event type
     */
    List<SecurityEvent> findByEventTypeOrderByTimestampDesc(String eventType);

    /**
     * Find security events by IP address
     */
    List<SecurityEvent> findByIpAddressOrderByTimestampDesc(String ipAddress);

    /**
     * Find recent failed login attempts for a user
     */
    @Query("SELECT COUNT(s) FROM SecurityEvent s WHERE s.username = :username AND s.eventType = 'LOGIN_FAILURE' AND s.timestamp >= :since")
    long countRecentFailedLogins(@Param("username") String username, @Param("since") LocalDateTime since);

    /**
     * Check if user has logged in from this IP before
     */
    @Query("SELECT COUNT(s) > 0 FROM SecurityEvent s WHERE s.username = :username AND s.ipAddress = :ipAddress AND s.timestamp >= :since")
    boolean existsByUsernameAndIpAddressAndTimestampAfter(@Param("username") String username,
                                                         @Param("ipAddress") String ipAddress,
                                                         @Param("since") LocalDateTime since);

    /**
     * Find high severity events
     */
    @Query("SELECT s FROM SecurityEvent s WHERE s.severity IN ('HIGH', 'CRITICAL') AND s.timestamp >= :since ORDER BY s.timestamp DESC")
    List<SecurityEvent> findHighSeverityEventsSince(@Param("since") LocalDateTime since);

    /**
     * Find events requiring investigation
     */
    List<SecurityEvent> findByRequiresInvestigationTrueOrderByTimestampDesc();

    /**
     * Find suspicious login patterns
     */
    @Query("SELECT s FROM SecurityEvent s WHERE s.eventType = 'LOGIN_FAILURE' AND s.timestamp >= :since GROUP BY s.ipAddress HAVING COUNT(s) >= :threshold")
    List<SecurityEvent> findSuspiciousLoginPatterns(@Param("since") LocalDateTime since, @Param("threshold") long threshold);

    /**
     * Find events within date range
     */
    @Query("SELECT s FROM SecurityEvent s WHERE s.timestamp BETWEEN :startDate AND :endDate ORDER BY s.timestamp DESC")
    List<SecurityEvent> findByTimestampBetween(@Param("startDate") LocalDateTime startDate,
                                             @Param("endDate") LocalDateTime endDate);

    /**
     * Count events by type in time period
     */
    @Query("SELECT COUNT(s) FROM SecurityEvent s WHERE s.eventType = :eventType AND s.timestamp >= :since")
    long countByEventTypeSince(@Param("eventType") String eventType, @Param("since") LocalDateTime since);

    /**
     * Find brute force attack patterns
     */
    @Query("SELECT s.ipAddress, COUNT(s) as attemptCount FROM SecurityEvent s WHERE s.eventType = 'LOGIN_FAILURE' AND s.timestamp >= :since GROUP BY s.ipAddress HAVING COUNT(s) >= :threshold")
    List<Object[]> findBruteForcePatterns(@Param("since") LocalDateTime since, @Param("threshold") long threshold);

    /**
     * Find data access anomalies
     */
    @Query("SELECT s FROM SecurityEvent s WHERE s.eventType = 'DATA_EXPORT' AND s.timestamp >= :since ORDER BY s.timestamp DESC")
    List<SecurityEvent> findDataExportEvents(@Param("since") LocalDateTime since);

    /**
     * Mark event as investigated
     */
    @Modifying
    @Query("UPDATE SecurityEvent s SET s.requiresInvestigation = false, s.investigatedAt = :timestamp, s.investigatedBy = :investigator WHERE s.id = :eventId")
    int markAsInvestigated(@Param("eventId") Long eventId, @Param("timestamp") LocalDateTime timestamp, @Param("investigator") String investigator);

    /**
     * Delete old security events (for retention policy)
     */
    @Modifying
    @Query("DELETE FROM SecurityEvent s WHERE s.timestamp < :cutoffDate")
    int deleteByTimestampBefore(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Find concurrent login attempts from different locations
     */
    @Query("SELECT s FROM SecurityEvent s WHERE s.eventType = 'LOGIN_SUCCESS' AND s.username = :username AND s.timestamp BETWEEN :startTime AND :endTime ORDER BY s.timestamp")
    List<SecurityEvent> findConcurrentLogins(@Param("username") String username,
                                           @Param("startTime") LocalDateTime startTime,
                                           @Param("endTime") LocalDateTime endTime);

    /**
     * Count unique IP addresses for user in time period
     */
    @Query("SELECT COUNT(DISTINCT s.ipAddress) FROM SecurityEvent s WHERE s.username = :username AND s.eventType = 'LOGIN_SUCCESS' AND s.timestamp >= :since")
    long countDistinctIpAddressesForUser(@Param("username") String username, @Param("since") LocalDateTime since);
}
