/**
 * PARTTIME JOB PLATFORM — MULTI-STEP REGISTRATION SERVICE
 *
 * Steps: Account Type → Personal Info → Phone OTP → Email OTP → Account Created
 *
 * Uses pending_registrations table to hold state server-side.
 * OTP purposes: phone_registration, email_registration
 * Phone OTP: sent via SMS provider if configured, otherwise via email as dev fallback.
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { pool, transaction } = require('./db');
const otpService = require('./otp');

// ─── Configuration ──────────────────────────────────────────────────────────

const REGISTRATION_EXPIRY_HOURS = 24; // pending registration expires after 24h
const PHONE_PURPOSE = 'phone_registration';
const EMAIL_PURPOSE = 'email_registration';

// ─── Helpers ────────────────────────────────────────────────────────────────

function generateRegToken() {
  return crypto.randomBytes(32).toString('hex');
}

function maskPhone(phone) {
  if (!phone || phone.length < 4) return '****';
  return '*'.repeat(phone.length - 4) + phone.slice(-4);
}

function maskEmail(email) {
  if (!email) return '';
  const [local, domain] = email.split('@');
  if (!domain) return email;
  if (local.length <= 2) return local[0] + '***@' + domain;
  return local[0] + '***' + local.slice(-1) + '@' + domain;
}

// ─── Phone OTP Sending ──────────────────────────────────────────────────────

/**
 * Send phone OTP. Uses SMS provider if configured (SMS_PROVIDER env),
 * otherwise falls back to email delivery for development.
 */
async function sendPhoneOtp(phone, code, senderName) {
  // Try SMS provider first
  if (process.env.SMS_PROVIDER) {
    try {
      const SmsProvider = getSmsProvider();
      if (SmsProvider) {
        await SmsProvider.send(phone, `Your ${senderName} verification code is: ${code}. It expires in 5 minutes. Do not share this code.`);
        return;
      }
    } catch (e) {
      console.error('[REGISTRATION] SMS send failed, falling back to email:', e.message);
    }
  }

  // Dev fallback: send phone OTP via email
  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
  });

  const to = process.env.DEV_PHONE_OTP_EMAIL || process.env.SMTP_FROM;
  if (!to) throw new Error('No email configured for phone OTP fallback. Set SMTP_FROM or DEV_PHONE_OTP_EMAIL.');

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject: `📱 Phone OTP: ${code}`,
    html: `
<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:480px;margin:40px auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#0d9488,#0891b2);padding:32px 24px;text-align:center;">
      <div style="font-size:28px;margin-bottom:8px;">📱</div>
      <h1 style="color:#fff;margin:0;font-size:22px;font-weight:700;">Phone Verification</h1>
    </div>
    <div style="padding:32px 24px;">
      <p style="color:#334155;font-size:15px;margin:0 0 16px;">Your phone verification code for <strong>${senderName}</strong>:</p>
      <div style="background:#f0fdfa;border:2px dashed #99f6e4;border-radius:12px;padding:20px;text-align:center;margin:24px 0;">
        <div style="font-size:36px;font-weight:800;letter-spacing:12px;color:#0d9488;font-family:monospace;">${code}</div>
      </div>
      <p style="color:#64748b;font-size:13px;margin:0 0 8px;">⏱ Expires in <strong>5 minutes</strong></p>
      <p style="color:#64748b;font-size:13px;margin:0;">🔒 Do not share this code.</p>
    </div>
  </div>
</body></html>`
  });
}

function getSmsProvider() {
  const provider = (process.env.SMS_PROVIDER || '').toLowerCase();
  if (provider === 'twilio') {
    // Twilio integration placeholder — requires TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER
    return {
      async send(to, body) {
        const accountSid = process.env.TWILIO_ACCOUNT_SID;
        const authToken = process.env.TWILIO_AUTH_TOKEN;
        const from = process.env.TWILIO_PHONE_NUMBER;
        if (!accountSid || !authToken || !from) throw new Error('Twilio credentials not configured');
        const url = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;
        const creds = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
        const resp = await fetch(url, {
          method: 'POST',
          headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ To: to, From: from, Body: body })
        });
        if (!resp.ok) {
          const err = await resp.text();
          throw new Error(`Twilio error: ${resp.status}`);
        }
      }
    };
  }
  return null;
}

// ─── Registration Flow ──────────────────────────────────────────────────────

/**
 * Step 1-2: Start registration — validates info, creates pending record.
 */
async function startRegistration(data, clientIp) {
  const { role, fullName, email, phone, password, ...profileData } = data;

  // Validate required fields
  if (!role || !['ROLE_STUDENT', 'ROLE_OWNER'].includes(role)) {
    return { success: false, message: 'Valid role (student or owner) is required', status: 400 };
  }
  if (!fullName || fullName.trim().length < 2) {
    return { success: false, message: 'Full name is required', status: 400 };
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { success: false, message: 'Enter a valid email address', status: 400 };
  }
  if (!phone || !/^\+?[\d\s-]{7,20}$/.test(phone.replace(/\s/g, ''))) {
    return { success: false, message: 'Enter a valid phone number', status: 400 };
  }
  if (!password || password.length < 6) {
    return { success: false, message: 'Password must be at least 6 characters', status: 400 };
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedPhone = phone.trim().replace(/\s+/g, '');

  // Check for existing email
  const [[existingEmail]] = await pool.query('SELECT id FROM users WHERE email=?', [normalizedEmail]);
  if (existingEmail) return { success: false, message: 'An account with this email already exists', status: 409 };

  // Check for existing phone
  const [[existingPhone]] = await pool.query('SELECT id FROM users WHERE phone=?', [normalizedPhone]);
  if (existingPhone) return { success: false, message: 'An account with this phone number already exists', status: 409 };

  // Check for pending registration with same email
  const [[pendingEmail]] = await pool.query(
    "SELECT id FROM pending_registrations WHERE email=? AND status='pending'",
    [normalizedEmail]
  );
  if (pendingEmail) {
    // Update existing pending registration
    const passwordHash = await bcrypt.hash(password, 10);
    const expiresAt = new Date(Date.now() + REGISTRATION_EXPIRY_HOURS * 3600 * 1000).toISOString();
    await pool.query(
      `UPDATE pending_registrations SET role=?, full_name=?, phone=?, password_hash=?,
       college_name=?, preferred_area=?, skills=?, bio=?, emergency_contact=?,
       catering_name=?, business_address=?, business_phone=?,
       phone_verified=0, email_verified=0, current_step='phone',
       status='pending', expires_at=?, updated_at=datetime('now','localtime')
       WHERE id=?`,
      [role, fullName.trim(), normalizedPhone, passwordHash,
       profileData.collegeName || null, profileData.preferredArea || null,
       profileData.skills || null, profileData.bio || null, profileData.emergencyContact || null,
       profileData.cateringName || null, profileData.businessAddress || null,
       profileData.businessPhone || null, expiresAt, pendingEmail.id]
    );
    // Invalidate old OTPs
    await pool.query(
      "UPDATE otp_verifications SET is_used=1 WHERE email=? AND purpose IN (?,?) AND is_verified=0",
      [normalizedEmail, PHONE_PURPOSE, EMAIL_PURPOSE]
    );
    return {
      success: true,
      registrationToken: (await pool.query('SELECT token FROM pending_registrations WHERE id=?', [pendingEmail.id]))[0][0].token,
      maskedPhone: maskPhone(normalizedPhone),
      maskedEmail: maskEmail(normalizedEmail),
      message: 'Registration information saved. Please verify your phone number.',
      currentStep: 'phone'
    };
  }

  // Create new pending registration
  const token = generateRegToken();
  const passwordHash = await bcrypt.hash(password, 10);
  const expiresAt = new Date(Date.now() + REGISTRATION_EXPIRY_HOURS * 3600 * 1000).toISOString();

  await pool.query(
    `INSERT INTO pending_registrations
     (token, role, full_name, email, phone, password_hash,
      college_name, preferred_area, skills, bio, emergency_contact,
      catering_name, business_address, business_phone,
      current_step, status, expires_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [token, role, fullName.trim(), normalizedEmail, normalizedPhone, passwordHash,
     profileData.collegeName || null, profileData.preferredArea || null,
     profileData.skills || null, profileData.bio || null, profileData.emergencyContact || null,
     profileData.cateringName || null, profileData.businessAddress || null,
     profileData.businessPhone || null, 'phone', 'pending', expiresAt]
  );

  return {
    success: true,
    registrationToken: token,
    maskedPhone: maskPhone(normalizedPhone),
    maskedEmail: maskEmail(normalizedEmail),
    message: 'Registration information saved. Please verify your phone number.',
    currentStep: 'phone'
  };
}

/**
 * Step 3a: Send phone OTP
 */
async function sendPhoneVerification(registrationToken, clientIp) {
  const [[pending]] = await pool.query(
    "SELECT * FROM pending_registrations WHERE token=? AND status='pending'",
    [registrationToken]
  );
  if (!pending) return { success: false, message: 'Invalid or expired registration session', status: 400 };
  if (pending.expires_at && new Date(pending.expires_at).getTime() < Date.now()) {
    await pool.query("UPDATE pending_registrations SET status='expired' WHERE id=?", [pending.id]);
    return { success: false, message: 'Registration session has expired. Please start again.', status: 400 };
  }

  const senderName = process.env.SMTP_SENDER_NAME || 'PartTime Job';
  const code = otpService.generateOtpCode();
  const otpHash = await otpService.hashOtp(code);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  // Invalidate previous phone OTPs for this pending registration
  await pool.query(
    "UPDATE otp_verifications SET is_used=1 WHERE email=? AND purpose=? AND is_verified=0",
    [pending.token, PHONE_PURPOSE]
  );

  // Store OTP with registration token as identifier
  await pool.query(
    'INSERT INTO otp_verifications (email, otp_hash, purpose, expires_at, max_attempts) VALUES (?,?,?,?,?)',
    [pending.token, otpHash, PHONE_PURPOSE, expiresAt, 5]
  );

  try {
    await sendPhoneOtp(pending.phone, code, senderName);
  } catch (e) {
    console.error('[REGISTRATION] Phone OTP send failed:', e.message);
    return { success: false, message: 'Failed to send verification code. Please try again.', status: 503 };
  }

  await pool.query(
    "UPDATE pending_registrations SET current_step='phone', updated_at=datetime('now','localtime') WHERE id=?",
    [pending.id]
  );

  return {
    success: true,
    maskedPhone: maskPhone(pending.phone),
    expiresIn: 300,
    message: 'Verification code sent to your phone'
  };
}

/**
 * Step 3b: Verify phone OTP
 */
async function verifyPhoneOtp(registrationToken, otp) {
  if (!otp || !/^\d{6}$/.test(otp)) {
    return { success: false, message: 'Enter the complete 6-digit code', status: 400 };
  }

  const [[pending]] = await pool.query(
    "SELECT * FROM pending_registrations WHERE token=? AND status='pending'",
    [registrationToken]
  );
  if (!pending) return { success: false, message: 'Invalid or expired registration session', status: 400 };

  // Find active phone OTP
  const [[otpRecord]] = await pool.query(
    "SELECT * FROM otp_verifications WHERE email=? AND purpose=? AND is_verified=0 AND is_used=0 ORDER BY created_at DESC LIMIT 1",
    [pending.token, PHONE_PURPOSE]
  );

  if (!otpRecord) return { success: false, message: 'No active verification code. Request a new one.', status: 400 };
  if (new Date(otpRecord.expires_at).getTime() < Date.now()) {
    return { success: false, message: 'Verification code has expired. Request a new one.', status: 400 };
  }
  if (otpRecord.attempts >= otpRecord.max_attempts) {
    return { success: false, message: 'Too many incorrect attempts. Request a new code.', status: 429 };
  }

  const matches = await otpService.verifyOtpHash(otp, otpRecord.otp_hash);
  if (!matches) {
    await pool.query('UPDATE otp_verifications SET attempts=attempts+1, updated_at=datetime(\'now\',\'localtime\') WHERE id=?', [otpRecord.id]);
    return { success: false, message: 'Incorrect verification code', status: 400 };
  }

  // Mark as verified
  await pool.query(
    "UPDATE otp_verifications SET is_verified=1, is_used=1, updated_at=datetime('now','localtime') WHERE id=?",
    [otpRecord.id]
  );
  await pool.query(
    "UPDATE pending_registrations SET phone_verified=1, current_step='email', updated_at=datetime('now','localtime') WHERE id=?",
    [pending.id]
  );

  return {
    success: true,
    maskedEmail: maskEmail(pending.email),
    message: 'Phone number verified successfully'
  };
}

/**
 * Step 4a: Send email OTP
 */
async function sendEmailVerification(registrationToken, clientIp) {
  const [[pending]] = await pool.query(
    "SELECT * FROM pending_registrations WHERE token=? AND status='pending'",
    [registrationToken]
  );
  if (!pending) return { success: false, message: 'Invalid or expired registration session', status: 400 };
  if (!pending.phone_verified) {
    return { success: false, message: 'Please verify your phone number first', status: 400 };
  }

  const senderName = process.env.SMTP_SENDER_NAME || 'PartTime Job';
  const code = otpService.generateOtpCode();
  const otpHash = await otpService.hashOtp(code);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  // Invalidate previous email OTPs for this registration
  await pool.query(
    "UPDATE otp_verifications SET is_used=1 WHERE email=? AND purpose=? AND is_verified=0",
    [pending.token, EMAIL_PURPOSE]
  );

  await pool.query(
    'INSERT INTO otp_verifications (email, otp_hash, purpose, expires_at, max_attempts) VALUES (?,?,?,?,?)',
    [pending.token, otpHash, EMAIL_PURPOSE, expiresAt, 5]
  );

  // Send email using the existing OTP service
  try {
    const senderEmail = process.env.SMTP_FROM;
    if (!senderEmail || !process.env.SMTP_HOST) {
      return { success: false, message: 'Email service is not configured. Please contact the administrator.', status: 503 };
    }

    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
    });

    await transporter.sendMail({
      from: senderEmail,
      to: pending.email,
      subject: `Verify Your Email — ${senderName}`,
      html: `
<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:480px;margin:40px auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:32px 24px;text-align:center;">
      <div style="font-size:28px;margin-bottom:8px;">✉️</div>
      <h1 style="color:#fff;margin:0;font-size:22px;font-weight:700;">Verify Your Email</h1>
    </div>
    <div style="padding:32px 24px;">
      <p style="color:#334155;font-size:15px;margin:0 0 16px;">Welcome to <strong>${senderName}</strong>! Confirm your email address.</p>
      <div style="background:#f8fafc;border:2px dashed #e2e8f0;border-radius:12px;padding:20px;text-align:center;margin:24px 0;">
        <div style="font-size:36px;font-weight:800;letter-spacing:12px;color:#4f46e5;font-family:monospace;">${code}</div>
      </div>
      <p style="color:#64748b;font-size:13px;margin:0 0 8px;">⏱ Expires in <strong>5 minutes</strong></p>
      <p style="color:#64748b;font-size:13px;margin:0;">🔒 Do not share this code with anyone.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0;">
      <p style="color:#94a3b8;font-size:12px;margin:0;">If you didn't request this, you can safely ignore this email.</p>
    </div>
  </div>
</body></html>`
    });
  } catch (e) {
    console.error('[REGISTRATION] Email send failed:', e.message);
    return { success: false, message: 'Failed to send verification email. Please try again.', status: 503 };
  }

  await pool.query(
    "UPDATE pending_registrations SET current_step='email', updated_at=datetime('now','localtime') WHERE id=?",
    [pending.id]
  );

  return {
    success: true,
    maskedEmail: maskEmail(pending.email),
    expiresIn: 300,
    message: 'Verification code sent to your email'
  };
}

/**
 * Step 4b: Verify email OTP
 */
async function verifyEmailOtp(registrationToken, otp) {
  if (!otp || !/^\d{6}$/.test(otp)) {
    return { success: false, message: 'Enter the complete 6-digit code', status: 400 };
  }

  const [[pending]] = await pool.query(
    "SELECT * FROM pending_registrations WHERE token=? AND status='pending'",
    [registrationToken]
  );
  if (!pending) return { success: false, message: 'Invalid or expired registration session', status: 400 };
  if (!pending.phone_verified) {
    return { success: false, message: 'Please verify your phone number first', status: 400 };
  }

  const [[otpRecord]] = await pool.query(
    "SELECT * FROM otp_verifications WHERE email=? AND purpose=? AND is_verified=0 AND is_used=0 ORDER BY created_at DESC LIMIT 1",
    [pending.token, EMAIL_PURPOSE]
  );

  if (!otpRecord) return { success: false, message: 'No active verification code. Request a new one.', status: 400 };
  if (new Date(otpRecord.expires_at).getTime() < Date.now()) {
    return { success: false, message: 'Verification code has expired. Request a new one.', status: 400 };
  }
  if (otpRecord.attempts >= otpRecord.max_attempts) {
    return { success: false, message: 'Too many incorrect attempts. Request a new code.', status: 429 };
  }

  const matches = await otpService.verifyOtpHash(otp, otpRecord.otp_hash);
  if (!matches) {
    await pool.query('UPDATE otp_verifications SET attempts=attempts+1, updated_at=datetime(\'now\',\'localtime\') WHERE id=?', [otpRecord.id]);
    return { success: false, message: 'Incorrect verification code', status: 400 };
  }

  await pool.query(
    "UPDATE otp_verifications SET is_verified=1, is_used=1, updated_at=datetime('now','localtime') WHERE id=?",
    [otpRecord.id]
  );
  await pool.query(
    "UPDATE pending_registrations SET email_verified=1, current_step='complete', updated_at=datetime('now','localtime') WHERE id=?",
    [pending.id]
  );

  return { success: true, message: 'Email verified successfully. Click "Complete Registration" to create your account.' };
}

/**
 * Step 5: Complete registration — create the actual user account.
 * Only succeeds if BOTH phone_verified=1 AND email_verified=1.
 */
async function completeRegistration(registrationToken) {
  const [[pending]] = await pool.query(
    "SELECT * FROM pending_registrations WHERE token=? AND status='pending'",
    [registrationToken]
  );
  if (!pending) return { success: false, message: 'Invalid or expired registration session', status: 400 };

  if (!pending.phone_verified || !pending.email_verified) {
    return { success: false, message: 'Both phone and email must be verified before completing registration', status: 400 };
  }

  // Create the user account in a transaction
  try {
    const result = await transaction(async c => {
      const [x] = await c.query(
        'INSERT INTO users (email, password_hash, full_name, phone, role, is_active) VALUES (?,?,?,?,?,?)',
        [pending.email, pending.password_hash, pending.full_name, pending.phone, pending.role, 1]
      );

      if (pending.role === 'ROLE_STUDENT') {
        await c.query(
          'INSERT INTO student_profiles (user_id, college_name, preferred_area, skills, bio, emergency_contact) VALUES (?,?,?,?,?,?)',
          [x.insertId, pending.college_name || null, pending.preferred_area || null,
           pending.skills || null, pending.bio || null, pending.emergency_contact || null]
        );
      } else {
        await c.query(
          'INSERT INTO owner_profiles (user_id, catering_name, business_address, business_phone) VALUES (?,?,?,?)',
          [x.insertId, pending.catering_name || pending.full_name,
           pending.business_address || null, pending.business_phone || pending.phone]
        );
      }

      // Mark pending registration as completed
      await c.query(
        "UPDATE pending_registrations SET status='completed', updated_at=datetime('now','localtime') WHERE id=?",
        [pending.id]
      );

      // Invalidate all OTPs for this registration
      await c.query(
        "UPDATE otp_verifications SET is_used=1 WHERE email=? AND purpose IN (?,?)",
        [pending.token, PHONE_PURPOSE, EMAIL_PURPOSE]
      );

      // Re-key verified OTP records from the registration token to the user's
      // real email so the login flow's verification check (which looks up by
      // email) recognizes accounts created through this multi-step wizard.
      await c.query(
        "UPDATE otp_verifications SET email=? WHERE email=? AND purpose IN (?,?) AND is_verified=1",
        [pending.email, pending.token, PHONE_PURPOSE, EMAIL_PURPOSE]
      );

      const [u] = await c.query('SELECT * FROM users WHERE id=?', [x.insertId]);
      return u[0];
    });

    // Generate JWT token
    const jwt = require('jsonwebtoken');
    const SECRET = process.env.JWT_SECRET || 'development-secret-change-me';
    const jwtToken = jwt.sign({ id: result.id, role: result.role }, SECRET, { expiresIn: '7d' });

    return {
      success: true,
      token: jwtToken,
      type: 'Bearer',
      id: result.id,
      email: result.email,
      fullName: result.full_name,
      phone: result.phone,
      role: result.role,
      active: !!result.is_active,
      suspended: !!result.is_suspended,
      message: 'Registration successful! Welcome to PartTime Job.'
    };
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') {
      return { success: false, message: 'Email or phone is already registered', status: 409 };
    }
    console.error('[REGISTRATION] Account creation failed:', e.message);
    return { success: false, message: 'Registration failed. Please try again.', status: 500 };
  }
}

/**
 * Get registration status
 */
async function getRegistrationStatus(registrationToken) {
  const [[pending]] = await pool.query(
    "SELECT token, role, phone_verified, email_verified, current_step, status, email, phone FROM pending_registrations WHERE token=?",
    [registrationToken]
  );
  if (!pending) return null;
  return {
    role: pending.role,
    phoneVerified: !!pending.phone_verified,
    emailVerified: !!pending.email_verified,
    currentStep: pending.current_step,
    status: pending.status,
    maskedPhone: maskPhone(pending.phone),
    maskedEmail: maskEmail(pending.email)
  };
}

/**
 * Resend phone OTP
 */
async function resendPhoneOtp(registrationToken, clientIp) {
  return sendPhoneVerification(registrationToken, clientIp);
}

/**
 * Resend email OTP
 */
async function resendEmailOtp(registrationToken, clientIp) {
  return sendEmailVerification(registrationToken, clientIp);
}

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = {
  startRegistration,
  sendPhoneVerification,
  verifyPhoneOtp,
  sendEmailVerification,
  verifyEmailOtp,
  completeRegistration,
  getRegistrationStatus,
  resendPhoneOtp,
  resendEmailOtp,
  maskPhone,
  maskEmail
};
