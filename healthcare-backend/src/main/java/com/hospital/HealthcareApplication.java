package com.healthcare;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Main application class for the Secure Healthcare Backend
 * Implements security measures against OWASP Top 10 vulnerabilities
 */
@SpringBootApplication
@EnableJpaAuditing
@EnableAsync
@EnableTransactionManagement
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@EnableConfigurationProperties
public class HealthcareApplication {

    public static void main(String[] args) {
        // Set system properties for security
        System.setProperty("java.awt.headless", "true");
        System.setProperty("file.encoding", "UTF-8");
        System.setProperty("user.timezone", "UTC");
        
        // Disable DNS caching for security
        System.setProperty("networkaddress.cache.ttl", "60");
        System.setProperty("networkaddress.cache.negative.ttl", "10");
        
        // Enhanced security properties
        System.setProperty("com.sun.management.jmxremote.authenticate", "true");
        System.setProperty("com.sun.management.jmxremote.ssl", "true");
        
        SpringApplication app = new SpringApplication(HealthcareApplication.class);
        
        // Additional security configuration
        app.setAdditionalProfiles(getActiveProfiles());
        app.run(args);
    }
    
    private static String[] getActiveProfiles() {
        String profile = System.getProperty("spring.profiles.active", "production");
        return new String[]{profile};
    }
}