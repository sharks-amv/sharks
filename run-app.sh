#!/bin/bash

# Export environment variables to configure database and security settings
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=healthcare_db
export DB_USERNAME=healthcare_user
export DB_PASSWORD=secure_password
export SSL_KEYSTORE_PASSWORD=changeit
export JWT_SECRET=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970
export ALLOWED_ORIGINS="http://localhost:3000,https://localhost:3000"

# Optional: Clear old build artifacts
./mvnw clean

# Build the project
./mvnw package

# Run the Spring Boot application
./mvnw spring-boot:run