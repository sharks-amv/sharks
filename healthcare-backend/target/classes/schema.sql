-- PostgreSQL Database Schema for Healthcare Management System
-- Implements security best practices and OWASP Top 10 protections

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table with comprehensive security features
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    phone_number VARCHAR(20),
    date_of_birth TIMESTAMP,
    role VARCHAR(20) NOT NULL CHECK (role IN ('PATIENT', 'DOCTOR', 'NURSE', 'ADMIN', 'STAFF')),
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_account_non_expired BOOLEAN NOT NULL DEFAULT true,
    is_account_non_locked BOOLEAN NOT NULL DEFAULT true,
    is_credentials_non_expired BOOLEAN NOT NULL DEFAULT true,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_login TIMESTAMP,
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT false,
    two_factor_secret VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    updated_by VARCHAR(100)
);

-- Indexes for performance and security
CREATE INDEX idx_users_username ON users(LOWER(username));
CREATE INDEX idx_users_email ON users(LOWER(email));
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login ON users(last_login);

-- Roles table for RBAC
CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table for fine-grained access control
CREATE TABLE permissions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    resource VARCHAR(50),
    action VARCHAR(20),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User-Role mapping
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Role-Permission mapping
CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Audit logs table for comprehensive logging
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id VARCHAR(100),
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent VARCHAR(500),
    details JSONB,
    session_id VARCHAR(100),
    severity VARCHAR(20) DEFAULT 'INFO'
);

-- Indexes for audit logs
CREATE INDEX idx_audit_username ON audit_logs(username);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_resource ON audit_logs(resource);
CREATE INDEX idx_audit_severity ON audit_logs(severity);

-- Security events table for security monitoring
CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address INET,
    details TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) DEFAULT 'LOW',
    user_agent VARCHAR(500),
    location VARCHAR(100),
    requires_investigation BOOLEAN DEFAULT false,
    investigated_at TIMESTAMP,
    investigated_by VARCHAR(100)
);

-- Indexes for security events
CREATE INDEX idx_security_username ON security_events(username);
CREATE INDEX idx_security_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_event_type ON security_events(event_type);
CREATE INDEX idx_security_ip_address ON security_events(ip_address);
CREATE INDEX idx_security_severity ON security_events(severity);
CREATE INDEX idx_security_investigation ON security_events(requires_investigation);

-- Patient-specific table (extends user)
CREATE TABLE patients (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    medical_record_number VARCHAR(50) UNIQUE NOT NULL,
    emergency_contact_name VARCHAR(100),
    emergency_contact_phone VARCHAR(20),
    insurance_provider VARCHAR(100),
    insurance_policy_number VARCHAR(100),
    allergies TEXT,
    medical_history TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Doctor-specific table (extends user)
CREATE TABLE doctors (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    license_number VARCHAR(100) UNIQUE NOT NULL,
    specialization VARCHAR(100),
    department VARCHAR(100),
    years_of_experience INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Appointments table
CREATE TABLE appointments (
    id BIGSERIAL PRIMARY KEY,
    patient_id BIGINT NOT NULL REFERENCES patients(id),
    doctor_id BIGINT NOT NULL REFERENCES doctors(id),
    appointment_date TIMESTAMP NOT NULL,
    duration_minutes INTEGER DEFAULT 30,
    status VARCHAR(20) DEFAULT 'SCHEDULED' CHECK (status IN ('SCHEDULED', 'CONFIRMED', 'COMPLETED', 'CANCELLED')),
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    updated_by VARCHAR(100)
);

-- Medical records table
CREATE TABLE medical_records (
    id BIGSERIAL PRIMARY KEY,
    patient_id BIGINT NOT NULL REFERENCES patients(id),
    doctor_id BIGINT NOT NULL REFERENCES doctors(id),
    appointment_id BIGINT REFERENCES appointments(id),
    diagnosis TEXT,
    treatment TEXT,
    prescription TEXT,
    notes TEXT,
    record_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES 
    ('ADMIN', 'System Administrator with full access'),
    ('DOCTOR', 'Medical Doctor with patient access'),
    ('NURSE', 'Nursing staff with limited patient access'),
    ('PATIENT', 'Patient with personal data access'),
    ('STAFF', 'General healthcare staff');

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action) VALUES 
    ('USER_READ', 'Read user information', 'User', 'READ'),
    ('USER_WRITE', 'Create/Update user information', 'User', 'WRITE'),
    ('USER_DELETE', 'Delete user accounts', 'User', 'DELETE'),
    ('PATIENT_READ', 'Read patient data', 'Patient', 'READ'),
    ('PATIENT_WRITE', 'Create/Update patient data', 'Patient', 'WRITE'),
    ('MEDICAL_RECORD_READ', 'Read medical records', 'MedicalRecord', 'READ'),
    ('MEDICAL_RECORD_WRITE', 'Create/Update medical records', 'MedicalRecord', 'WRITE'),
    ('APPOINTMENT_READ', 'Read appointment data', 'Appointment', 'READ'),
    ('APPOINTMENT_WRITE', 'Create/Update appointments', 'Appointment', 'WRITE'),
    ('ADMIN_PANEL_ACCESS', 'Access admin panel', 'AdminPanel', 'ACCESS'),
    ('AUDIT_LOG_READ', 'Read audit logs', 'AuditLog', 'READ'),
    ('SECURITY_EVENT_READ', 'Read security events', 'SecurityEvent', 'READ');

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id) VALUES 
    -- ADMIN permissions (all)
    (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8), (1, 9), (1, 10), (1, 11), (1, 12),
    -- DOCTOR permissions
    (2, 1), (2, 4), (2, 5), (2, 6), (2, 7), (2, 8), (2, 9),
    -- NURSE permissions  
    (3, 1), (3, 4), (3, 6), (3, 8),
    -- PATIENT permissions (limited)
    (4, 1), (4, 4), (4, 6), (4, 8),
    -- STAFF permissions
    (5, 1), (5, 4), (5, 8);

-- Create function to update timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_patients_updated_at BEFORE UPDATE ON patients 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_doctors_updated_at BEFORE UPDATE ON doctors 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_appointments_updated_at BEFORE UPDATE ON appointments 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_medical_records_updated_at BEFORE UPDATE ON medical_records 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) for data protection
ALTER TABLE patients ENABLE ROW LEVEL SECURITY;
ALTER TABLE medical_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE appointments ENABLE ROW LEVEL SECURITY;

-- Policies for patients table - patients can only see their own data
CREATE POLICY patient_policy ON patients
    FOR ALL TO PUBLIC
    USING (user_id = (SELECT id FROM users WHERE username = current_user));

-- Policies for medical records - patients can see their own, doctors can see their patients'
CREATE POLICY medical_record_patient_policy ON medical_records
    FOR SELECT TO PUBLIC
    USING (patient_id IN (SELECT id FROM patients WHERE user_id = (SELECT id FROM users WHERE username = current_user)));

CREATE POLICY medical_record_doctor_policy ON medical_records
    FOR ALL TO PUBLIC
    USING (doctor_id IN (SELECT id FROM doctors WHERE user_id = (SELECT id FROM users WHERE username = current_user)));

-- Create indexes for performance
CREATE INDEX idx_patients_user_id ON patients(user_id);
CREATE INDEX idx_doctors_user_id ON doctors(user_id);
CREATE INDEX idx_appointments_patient_id ON appointments(patient_id);
CREATE INDEX idx_appointments_doctor_id ON appointments(doctor_id);
CREATE INDEX idx_appointments_date ON appointments(appointment_date);
CREATE INDEX idx_medical_records_patient_id ON medical_records(patient_id);
CREATE INDEX idx_medical_records_doctor_id ON medical_records(doctor_id);
CREATE INDEX idx_medical_records_date ON medical_records(record_date);

-- Comments for documentation
COMMENT ON TABLE users IS 'Main users table with comprehensive security features';
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail for compliance and security monitoring';
COMMENT ON TABLE security_events IS 'Security event logging for threat detection and response';
COMMENT ON COLUMN users.password IS 'Argon2 hashed password - never store plain text';
COMMENT ON COLUMN users.failed_login_attempts IS 'Failed login counter for account lockout protection';
COMMENT ON COLUMN users.two_factor_secret IS 'TOTP secret for two-factor authentication';