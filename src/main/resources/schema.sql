-- ==================================================================================
-- DATABASE SCHEMA: PartTime Job Platform (MySQL 8+)
-- ==================================================================================

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    role VARCHAR(30) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_email (email),
    INDEX idx_user_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Student Profiles
CREATE TABLE IF NOT EXISTS student_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    college_name VARCHAR(150),
    preferred_area VARCHAR(100),
    skills TEXT,
    bio TEXT,
    emergency_contact VARCHAR(20),
    profile_photo_url TEXT,
    total_jobs_completed INT DEFAULT 0,
    rating DOUBLE DEFAULT 5.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_student_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_student_pref_area (preferred_area)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Owner Profiles
CREATE TABLE IF NOT EXISTS owner_profiles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    catering_name VARCHAR(150) NOT NULL,
    business_address TEXT,
    business_phone VARCHAR(20),
    verification_status VARCHAR(30) DEFAULT 'PENDING_VERIFICATION',
    verified_at TIMESTAMP NULL,
    profile_photo_url TEXT,
    total_jobs_posted INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_owner_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_owner_catering_name (catering_name),
    INDEX idx_owner_verification (verification_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Catering Jobs
CREATE TABLE IF NOT EXISTS catering_jobs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    owner_id BIGINT NOT NULL,
    title VARCHAR(150) NOT NULL,
    description TEXT,
    work_type VARCHAR(50) NOT NULL,
    work_area VARCHAR(100) NOT NULL,
    detailed_location TEXT NOT NULL,
    job_date DATE NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    payment_amount DECIMAL(10, 2) NOT NULL,
    payment_type VARCHAR(50) NOT NULL,
    is_on_spot_payment BOOLEAN DEFAULT TRUE,
    workers_required INT NOT NULL,
    workers_selected INT DEFAULT 0,
    required_skills VARCHAR(255),
    contact_phone VARCHAR(20) NOT NULL,
    contact_email VARCHAR(120),
    location_photo_url TEXT,
    latitude DOUBLE NULL,
    longitude DOUBLE NULL,
    location_address TEXT,
    status VARCHAR(30) DEFAULT 'OPEN',
    apply_deadline DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_job_owner FOREIGN KEY (owner_id) REFERENCES owner_profiles(id) ON DELETE CASCADE,
    INDEX idx_job_area (work_area),
    INDEX idx_job_date (job_date),
    INDEX idx_job_work_type (work_type),
    INDEX idx_job_status (status),
    INDEX idx_job_payment (payment_amount)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Job Applications
CREATE TABLE IF NOT EXISTS job_applications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    job_id BIGINT NOT NULL,
    student_id BIGINT NOT NULL,
    status VARCHAR(30) DEFAULT 'APPLIED',
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP NULL,
    attendance_status VARCHAR(30) DEFAULT 'NOT_MARKED',
    work_completion_status VARCHAR(30) DEFAULT 'NOT_COMPLETED',
    razorpay_receipt VARCHAR(255) NULL,
    payment_status VARCHAR(30) DEFAULT 'PENDING',
    payment_amount DECIMAL(10, 2) NOT NULL,
    payment_confirmation_date TIMESTAMP NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_app_job FOREIGN KEY (job_id) REFERENCES catering_jobs(id) ON DELETE CASCADE,
    CONSTRAINT fk_app_student FOREIGN KEY (student_id) REFERENCES student_profiles(id) ON DELETE CASCADE,
    UNIQUE KEY uq_job_student (job_id, student_id),
    INDEX idx_app_status (status),
    INDEX idx_app_payment_status (payment_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Payment Records
CREATE TABLE IF NOT EXISTS payment_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    application_id BIGINT NOT NULL UNIQUE,
    job_id BIGINT NOT NULL,
    student_id BIGINT NOT NULL,
    owner_id BIGINT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    payment_type VARCHAR(50) NOT NULL,
    razorpay_receipt VARCHAR(255) NULL,
    payment_status VARCHAR(30) DEFAULT 'PENDING',
    marked_paid_at TIMESTAMP NULL,
    confirmed_paid_at TIMESTAMP NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_pay_app FOREIGN KEY (application_id) REFERENCES job_applications(id) ON DELETE CASCADE,
    CONSTRAINT fk_pay_job FOREIGN KEY (job_id) REFERENCES catering_jobs(id) ON DELETE CASCADE,
    CONSTRAINT fk_pay_student FOREIGN KEY (student_id) REFERENCES student_profiles(id) ON DELETE CASCADE,
    CONSTRAINT fk_pay_owner FOREIGN KEY (owner_id) REFERENCES owner_profiles(id) ON DELETE CASCADE,
    INDEX idx_pay_status (payment_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Reports / Complaints
CREATE TABLE IF NOT EXISTS reports (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    reporter_id BIGINT NOT NULL,
    target_user_id BIGINT NOT NULL,
    job_id BIGINT NULL,
    application_id BIGINT NULL,
    report_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    expected_amount DECIMAL(10, 2) NULL,
    received_amount DECIMAL(10, 2) NULL,
    evidence_notes TEXT,
    status VARCHAR(30) DEFAULT 'PENDING',
    admin_remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    CONSTRAINT fk_rep_reporter FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_rep_target FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_rep_job FOREIGN KEY (job_id) REFERENCES catering_jobs(id) ON DELETE SET NULL,
    CONSTRAINT fk_rep_app FOREIGN KEY (application_id) REFERENCES job_applications(id) ON DELETE SET NULL,
    INDEX idx_rep_status (status),
    INDEX idx_rep_type (report_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    recipient_id BIGINT NOT NULL,
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    type VARCHAR(50) NOT NULL,
    related_entity_id BIGINT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_notif_recipient FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_notif_recipient (recipient_id),
    INDEX idx_notif_read (is_read)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. Job Deletion Requests
CREATE TABLE IF NOT EXISTS job_deletion_requests (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    job_id BIGINT NOT NULL,
    owner_id BIGINT NOT NULL,
    student_id BIGINT NOT NULL,
    status VARCHAR(30) DEFAULT 'PENDING',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP NULL,
    CONSTRAINT fk_delreq_job FOREIGN KEY (job_id) REFERENCES catering_jobs(id) ON DELETE CASCADE,
    CONSTRAINT fk_delreq_owner FOREIGN KEY (owner_id) REFERENCES owner_profiles(id) ON DELETE CASCADE,
    CONSTRAINT fk_delreq_student FOREIGN KEY (student_id) REFERENCES student_profiles(id) ON DELETE CASCADE,
    INDEX idx_delreq_job (job_id),
    INDEX idx_delreq_student (student_id),
    INDEX idx_delreq_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. OTP Verifications
CREATE TABLE IF NOT EXISTS otp_verifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(120) NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    purpose VARCHAR(30) NOT NULL DEFAULT 'registration',
    expires_at TIMESTAMP NOT NULL,
    attempts INT DEFAULT 0,
    max_attempts INT DEFAULT 5,
    is_verified BOOLEAN DEFAULT FALSE,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_otp_email_purpose (email, purpose),
    INDEX idx_otp_expires (expires_at),
    INDEX idx_otp_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10b. Pending Registrations (multi-step registration state)
CREATE TABLE IF NOT EXISTS pending_registrations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    role VARCHAR(30) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    -- Student-specific
    college_name VARCHAR(150),
    preferred_area VARCHAR(100),
    skills TEXT,
    bio TEXT,
    emergency_contact VARCHAR(20),
    -- Owner-specific
    catering_name VARCHAR(150),
    business_address TEXT,
    business_phone VARCHAR(20),
    -- Verification state (server-authoritative)
    phone_verified INTEGER DEFAULT 0,
    email_verified INTEGER DEFAULT 0,
    status VARCHAR(30) DEFAULT 'pending',
    current_step VARCHAR(30) DEFAULT 'info',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT NOT NULL,
    INDEX idx_pend_token (token),
    INDEX idx_pend_email (email),
    INDEX idx_pend_phone (phone)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 11. Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NULL,
    action VARCHAR(100) NOT NULL,
    entity_name VARCHAR(50) NOT NULL,
    entity_id BIGINT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
