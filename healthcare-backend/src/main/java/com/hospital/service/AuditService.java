package com.healthcare.service;

import com.healthcare.entity.AuditLog;
import com.healthcare.entity.SecurityEvent;
import com.healthcare.repository.AuditLogRepository;
import com.healthcare.repository.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Audit Service for security logging and monitoring
 * Implements A09: Security Logging and Monitoring Failures protection
 */
@Service
@Transactional
public class AuditService {

    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");

    private final AuditLogRepository auditLogRepository;
    private final SecurityEventRepository securityEventRepository;

    public AuditService(AuditLogRepository auditLogRepository,
                       SecurityEventRepository securityEventRepository) {
        this.auditLogRepository = auditLogRepository;
        this.securityEventRepository = securityEventRepository;
    }

    /**
     * Log user action for audit trail
     */
    @Async
    public void logUserAction(String username, String action, String resource, 
                             String resourceId, Map<String, Object> details) {
        try {
            AuditLog auditLog = new AuditLog();
            auditLog.setUsername(username);
            auditLog.setAction(action);
            auditLog.setResource(resource);
            auditLog.setResourceId(resourceId);
            auditLog.setDetails(details);
            auditLog.setTimestamp(LocalDateTime.now());
            auditLog.setIpAddress(getCurrentUserIP());
            auditLog.setUserAgent(getCurrentUserAgent());

            auditLogRepository.save(auditLog);

            // Also log to file for external SIEM systems
            auditLogger.info("User: {} | Action: {} | Resource: {} | ResourceId: {} | IP: {} | Timestamp: {}",
                    username, action, resource, resourceId, auditLog.getIpAddress(), auditLog.getTimestamp());

        } catch (Exception e) {
            logger.error("Failed to log audit event", e);
        }
    }

    /**
     * Log security event (authentication, authorization, etc.)
     */
    @Async
    public void logSecurityEvent(String username, String eventType, String ipAddress, String details) {
        try {
            SecurityEvent event = new SecurityEvent();
            event.setUsername(username);
            event.setEventType(eventType);
            event.setIpAddress(ipAddress);
            event.setDetails(details);
            event.setTimestamp(LocalDateTime.now());
            event.setSeverity(determineSeverity(eventType));

            securityEventRepository.save(event);

            // Log to security log file
            securityLogger.warn("Security Event: {} | User: {} | IP: {} | Details: {} | Severity: {}",
                    eventType, username, ipAddress, details, event.getSeverity());

            // Check for suspicious patterns
            checkForSuspiciousActivity(username, eventType, ipAddress);

        } catch (Exception e) {
            logger.error("Failed to log security event", e);
        }
    }

    /**
     * Log login attempt
     */
    public void logLoginAttempt(String username, String ipAddress, boolean successful, String failureReason) {
        String eventType = successful ? "LOGIN_SUCCESS" : "LOGIN_FAILURE";
        String details = successful ? "User logged in successfully" : "Login failed: " + failureReason;
        
        logSecurityEvent(username, eventType, ipAddress, details);
    }

    /**
     * Log logout event
     */
    public void logLogout(String username, String ipAddress) {
        logSecurityEvent(username, "LOGOUT", ipAddress, "User logged out");
    }

    /**
     * Log password change
     */
    public void logPasswordChange(String username, String ipAddress, boolean successful) {
        String eventType = successful ? "PASSWORD_CHANGE_SUCCESS" : "PASSWORD_CHANGE_FAILURE";
        logSecurityEvent(username, eventType, ipAddress, "Password change attempt");
    }

    /**
     * Log permission denied events
     */
    public void logAccessDenied(String username, String resource, String action, String ipAddress) {
        logSecurityEvent(username, "ACCESS_DENIED", ipAddress, 
                String.format("Access denied for action '%s' on resource '%s'", action, resource));
    }

    /**
     * Log data access events (for HIPAA compliance)
     */
    public void logDataAccess(String username, String dataType, String recordId, String action) {
        Map<String, Object> details = Map.of(
                "dataType", dataType,
                "recordId", recordId,
                "action", action,
                "timestamp", LocalDateTime.now().toString()
        );
        
        logUserAction(username, "DATA_ACCESS", dataType, recordId, details);
    }

    /**
     * Log sensitive data export
     */
    public void logDataExport(String username, String exportType, int recordCount) {
        Map<String, Object> details = Map.of(
                "exportType", exportType,
                "recordCount", recordCount,
                "timestamp", LocalDateTime.now().toString()
        );
        
        logUserAction(username, "DATA_EXPORT", exportType, null, details);
        
        // High-priority security event for data exports
        logSecurityEvent(username, "DATA_EXPORT", getCurrentUserIP(), 
                String.format("Exported %d records of type %s", recordCount, exportType));
    }

    /**
     * Determine severity based on event type
     */
    private String determineSeverity(String eventType) {
        return switch (eventType) {
            case "LOGIN_FAILURE", "ACCESS_DENIED", "INVALID_TOKEN" -> "MEDIUM";
            case "DATA_EXPORT", "PRIVILEGE_ESCALATION", "SQL_INJECTION_ATTEMPT" -> "HIGH";
            case "SYSTEM_COMPROMISE", "DATA_BREACH" -> "CRITICAL";
            default -> "LOW";
        };
    }

    /**
     * Check for suspicious activity patterns
     */
    private void checkForSuspiciousActivity(String username, String eventType, String ipAddress) {
        // Check for multiple failed login attempts
        if ("LOGIN_FAILURE".equals(eventType)) {
            long recentFailures = securityEventRepository.countRecentFailedLogins(username, 
                    LocalDateTime.now().minusMinutes(15));
            
            if (recentFailures >= 5) {
                logSecurityEvent(username, "SUSPICIOUS_ACTIVITY", ipAddress, 
                        "Multiple failed login attempts detected");
            }
        }

        // Check for login from new IP
        if ("LOGIN_SUCCESS".equals(eventType)) {
            boolean isNewIP = !securityEventRepository.existsByUsernameAndIpAddressAndTimestampAfter(
                    username, ipAddress, LocalDateTime.now().minusDays(30));
            
            if (isNewIP) {
                logSecurityEvent(username, "NEW_IP_LOGIN", ipAddress, 
                        "Login from previously unseen IP address");
            }
        }
    }

    /**
     * Get current user's IP address (placeholder - implement based on your context)
     */
    private String getCurrentUserIP() {
        // This would typically get IP from SecurityContext or request
        return "0.0.0.0"; // Placeholder
    }

    /**
     * Get current user's User-Agent (placeholder - implement based on your context)
     */
    private String getCurrentUserAgent() {
        // This would typically get User-Agent from current request
        return "Unknown"; // Placeholder
    }

    /**
     * Clean up old audit logs based on retention policy
     */
    @Async
    public void cleanupOldLogs() {
        try {
            LocalDateTime cutoffDate = LocalDateTime.now().minusDays(365); // 1 year retention
            
            int deletedAuditLogs = auditLogRepository.deleteByTimestampBefore(cutoffDate);
            int deletedSecurityEvents = securityEventRepository.deleteByTimestampBefore(cutoffDate);
            
            logger.info("Cleanup completed: {} audit logs and {} security events deleted", 
                    deletedAuditLogs, deletedSecurityEvents);
            
        } catch (Exception e) {
            logger.error("Failed to cleanup old logs", e);
        }
    }
}