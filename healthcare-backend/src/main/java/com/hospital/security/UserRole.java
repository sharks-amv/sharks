package com.healthcare.entity;

/**
 * User role enumeration for access control
 * Implements A01: Broken Access Control protection
 */
public enum UserRole {
    PATIENT("Patient", "Regular patient user"),
    DOCTOR("Doctor", "Medical doctor user"),
    NURSE("Nurse", "Nursing staff user"),
    ADMIN("Administrator", "System administrator"),
    STAFF("Staff", "General healthcare staff");

    private final String displayName;
    private final String description;

    UserRole(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Get role with ROLE_ prefix for Spring Security
     */
    public String getAuthority() {
        return "ROLE_" + this.name();
    }
}