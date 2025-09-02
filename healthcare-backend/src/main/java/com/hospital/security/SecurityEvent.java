package com.healthcare.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Security Event entity for tracking security-related events
 * Implements A09: Security Logging and Monitoring Failures protection
 */
@Entity
@Table(name = "security_events", indexes = {
    @Index(name = "idx_security_username", columnList = "username"),
    @Index(name = "idx_security_timestamp", columnList = "timestamp"),
    @Index(name = "idx_security_event_type", columnList = "event_type"),
    @Index(name = "idx_security_ip_address", columnList = "ip_address"),
    @Index(name = "idx_security_severity", columnList = "severity")
})
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String username;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(length = 1000)
    private String details;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(length = 20)
    private String severity = "LOW";

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(length = 100)
    private String location;

    @Column(name = "requires_investigation")
    private Boolean requiresInvestigation = false;

    @Column(name = "investigated_at")
    private LocalDateTime investigatedAt;

    @Column(name = "investigated_by", length = 100)
    private String investigatedBy;

    // Default constructor
    public SecurityEvent() {}

    // Constructor with required fields
    public SecurityEvent(String username, String eventType, String ipAddress, LocalDateTime timestamp) {
        this.username = username;
        this.eventType = eventType;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public Boolean getRequiresInvestigation() {
        return requiresInvestigation;
    }

    public void setRequiresInvestigation(Boolean requiresInvestigation) {
        this.requiresInvestigation = requiresInvestigation;
    }

    public LocalDateTime getInvestigatedAt() {
        return investigatedAt;
    }

    public void setInvestigatedAt(LocalDateTime investigatedAt) {
        this.investigatedAt = investigatedAt;
    }

    public String getInvestigatedBy() {
        return investigatedBy;
    }

    public void setInvestigatedBy(String investigatedBy) {
        this.investigatedBy = investigatedBy;
    }

    @Override
    public String toString() {
        return "SecurityEvent{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", eventType='" + eventType + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", timestamp=" + timestamp +
                ", severity='" + severity + '\'' +
                '}';
    }
}