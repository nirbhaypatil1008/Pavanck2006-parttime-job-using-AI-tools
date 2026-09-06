require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {pool, initializeDatabase, transaction} = require('./server/db');
const otpService = require('./server/otp');
const regService = require('./server/register');
const chatRouter = require('./server/chat');
const razorpayRouter = require('./server/razorpay');
const {createOrUpdateTransaction, updateTransactionStatus, getTransactionDetails, getTransactionsList, getTransactionSummary} = require('./server/transactions');
const multer = require('multer');

// File upload config
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, {recursive: true});
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `job-photo-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`);
  }
});
const upload = multer({
  storage, limits: {fileSize: 5 * 1024 * 1024},
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|jpg|png|gif|webp)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only image files (JPG, PNG, GIF, WebP) are allowed.'));
  }
});

const app = express();
const PORT = Number(process.env.PORT || 8080);
const SECRET = process.env.JWT_SECRET || 'development-secret-change-me';
const staticDir = path.join(__dirname, 'src', 'main', 'resources', 'static');


app.use(express.json({limit: '1mb'}));
app.use(express.urlencoded({extended: true}));
app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

// ─── STATIC FILES (served before auth so /, /css/*, /js/* work without JWT) ──
app.use(express.static(path.join(__dirname, 'uploads')));
app.use(express.static(staticDir));

const ok = (res, data, message) => res.json({data, ...(message ? {message} : {})});
const fail = (res, status, message) => res.status(status).json({message});
const guard = (...roles) => (req, res, next) => req.user && roles.includes(req.user.role) ? next() : fail(res, 403, 'You do not have permission for this action');

// Wire up auth before DELETE on reports
app.use('/api/reports/:id', (req, res, next) => req.method === 'DELETE' ? auth(req, res, () => guard('ROLE_STUDENT')(req, res, next)) : next());
app.use('/api/chat', auth, chatRouter);
// Razorpay public key endpoint (no auth required)
app.get('/api/public/razorpay-key', (req, res) => {
  const keyId = process.env.RAZORPAY_KEY_ID || '';
  ok(res, {apiKey: keyId, configured: !!keyId});
});

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return fail(res, 401, 'Authentication is required');
    const c = jwt.verify(token, SECRET);
    const [r] = await pool.query('SELECT * FROM users WHERE id=?', [c.id]);
    if (!r[0] || !r[0].is_active || r[0].is_suspended) return fail(res, 401, 'Account is inactive or suspended');
    req.user = r[0];
    next();
  } catch { fail(res, 401, 'Invalid or expired token'); }
}

function token(user, extra = {}) {
  return {
    token: jwt.sign({id: user.id, role: user.role}, SECRET, {expiresIn: '7d'}),
    type: 'Bearer', id: user.id, email: user.email, fullName: user.full_name,
    phone: user.phone, role: user.role, active: !!user.is_active,
    suspended: !!user.is_suspended, ...extra
  };
}

async function sendEmailOtp(destination, code) {
  // Delegate to OTP service which handles Nodemailer
  await otpService.sendEmail(destination, code, otpService.OTP_EXPIRY_MINUTES);
}

// ─── MULTI-STEP REGISTRATION ──────────────────────────────────────────────

app.post('/api/auth/register/start', async (req, res, next) => {
  try {
    const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
    const result = await regService.startRegistration(req.body, clientIp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, {
      registrationToken: result.registrationToken,
      maskedPhone: result.maskedPhone,
      maskedEmail: result.maskedEmail,
      currentStep: result.currentStep
    }, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register/phone/send', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    if (!token) return fail(res, 400, 'Registration token is required');
    const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
    const result = await regService.sendPhoneVerification(token, clientIp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, { maskedPhone: result.maskedPhone, expiresIn: result.expiresIn }, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register/phone/verify', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    const otp = req.body.otp;
    if (!token) return fail(res, 400, 'Registration token is required');
    const result = await regService.verifyPhoneOtp(token, otp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, { maskedEmail: result.maskedEmail }, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register/email/send', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    if (!token) return fail(res, 400, 'Registration token is required');
    const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
    const result = await regService.sendEmailVerification(token, clientIp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, { maskedEmail: result.maskedEmail, expiresIn: result.expiresIn }, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register/email/verify', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    const otp = req.body.otp;
    if (!token) return fail(res, 400, 'Registration token is required');
    const result = await regService.verifyEmailOtp(token, otp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, null, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register/complete', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    if (!token) return fail(res, 400, 'Registration token is required');
    const result = await regService.completeRegistration(token);
    if (!result.success) return fail(res, result.status || 500, result.message);
    const { success, ...authData } = result;
    ok(res, authData, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register/status', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    if (!token) return fail(res, 400, 'Registration token is required');
    const status = await regService.getRegistrationStatus(token);
    if (!status) return fail(res, 404, 'Registration session not found or expired');
    ok(res, status, 'Registration status retrieved');
  } catch (e) { next(e); }
});

app.post('/api/auth/register/resend-phone', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    if (!token) return fail(res, 400, 'Registration token is required');
    const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
    const result = await regService.resendPhoneOtp(token, clientIp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, { maskedPhone: result.maskedPhone, expiresIn: result.expiresIn }, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register/resend-email', async (req, res, next) => {
  try {
    const token = req.body.registrationToken || req.body.token;
    if (!token) return fail(res, 400, 'Registration token is required');
    const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
    const result = await regService.resendEmailOtp(token, clientIp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, { maskedEmail: result.maskedEmail, expiresIn: result.expiresIn }, result.message);
  } catch (e) { next(e); }
});

// ─── AUTH (Legacy — kept for backward compat) ───────────────────────────────

app.post('/api/auth/request-otp', async (req, res, next) => {
  try {
    const destination = String(req.body.email || '').trim().toLowerCase();
    if (!destination || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(destination)) return fail(res, 400, 'Enter a valid email address');
    const [existing] = await pool.query('SELECT id FROM users WHERE email=?', [destination]);
    if (existing[0]) return fail(res, 409, 'That email is already registered');
    const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
    const result = await otpService.sendOtp(destination, 'registration', clientIp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    // Find the verification ID we just created
    const [[otpRecord]] = await pool.query(
      'SELECT id FROM otp_verifications WHERE email=? AND purpose=? ORDER BY created_at DESC LIMIT 1',
      [destination, 'registration']
    );
    ok(res, {verificationId: otpRecord ? String(otpRecord.id) : '0', expiresInSeconds: result.expiresIn}, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/verify-otp', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const otp = String(req.body.otp || '');
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Enter a valid email address');
    const result = await otpService.verifyOtp(email, 'registration', otp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    ok(res, {verificationId: String(result.verificationId)}, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const b = req.body;
    if (!b.fullName || !b.email || !b.password || !b.phone || !['ROLE_STUDENT', 'ROLE_OWNER'].includes(b.role))
      return fail(res, 400, 'Full name, email, password, phone and a valid role are required');
    const destination = String(b.email).trim().toLowerCase();
    // Verify that email was verified via OTP
    const verified = await otpService.isVerified(b.verificationId, destination, 'registration');
    if (!verified)
      return fail(res, 400, 'Verify your email before creating the account');
    // Invalidate the OTP record now that registration is proceeding
    await otpService.invalidateVerification(b.verificationId);
    const data = await transaction(async c => {
      const [x] = await c.query('INSERT INTO users (email,password_hash,full_name,phone,role,is_active) VALUES (?,?,?,?,?,?)',
        [b.email.toLowerCase(), await bcrypt.hash(b.password, 10), b.fullName, b.phone, b.role, 1]);
      if (b.role === 'ROLE_STUDENT') {
        await c.query('INSERT INTO student_profiles (user_id,college_name,preferred_area,skills,bio,emergency_contact) VALUES (?,?,?,?,?,?)',
          [x.insertId, b.collegeName || null, b.preferredArea || null, b.skills || null, b.bio || null, b.emergencyContact || null]);
      } else {
        await c.query('INSERT INTO owner_profiles (user_id,catering_name,business_address,business_phone) VALUES (?,?,?,?)',
          [x.insertId, b.cateringName || b.fullName, b.businessAddress || null, b.businessPhone || b.phone]);
      }
      const [u] = await c.query('SELECT * FROM users WHERE id=?', [x.insertId]);
      return token(u[0]);
    });
    ok(res, data, 'Registration successful! Welcome to PartTime Job.');
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return fail(res, 409, 'Email or phone is already registered');
    next(e);
  }
});

app.post('/api/auth/resend-otp', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const purpose = req.body.purpose || 'registration';
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Enter a valid email address');
    if (purpose === 'registration') {
      const [existing] = await pool.query('SELECT id FROM users WHERE email=?', [email]);
      if (existing[0]) return fail(res, 409, 'That email is already registered');
    }
    const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
    const result = await otpService.resendOtp(email, purpose, clientIp);
    if (!result.success) return fail(res, result.status || 500, result.message);
    const [[otpRecord]] = await pool.query(
      'SELECT id FROM otp_verifications WHERE email=? AND purpose=? ORDER BY created_at DESC LIMIT 1',
      [email, purpose]
    );
    ok(res, {verificationId: otpRecord ? String(otpRecord.id) : '0', expiresInSeconds: result.expiresIn}, result.message);
  } catch (e) { next(e); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const [r] = await pool.query('SELECT * FROM users WHERE email=?', [(req.body.email || '').toLowerCase()]);
    const u = r[0];
    if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash))) return fail(res, 401, 'Invalid email or password');
    if (u.is_suspended || !u.is_active) return fail(res, 403, 'Your account is suspended or inactive');
    // Check if email was verified via OTP during registration (skip for admin accounts)
    if (u.role !== 'ROLE_ADMIN') {
      const [[otpVerified]] = await pool.query(
        "SELECT id FROM otp_verifications WHERE email=? AND purpose IN ('registration','email_registration') AND is_verified=1 AND is_used=1 LIMIT 1",
        [u.email]
      );
      if (!otpVerified) return fail(res, 403, 'Email verification is required. Please verify your email to continue.');
      // Also check phone verification for users registered via the new flow
      const [[phoneVerified]] = await pool.query(
        "SELECT id FROM otp_verifications WHERE email=? AND purpose='phone_registration' AND is_verified=1 AND is_used=1 LIMIT 1",
        [u.email]
      );
      // For legacy users (no phone_registration OTP), allow login; only block if phone_registration purpose was started
      // This ensures backward compatibility with existing accounts
    }
    let extra = {};
    if (u.role === 'ROLE_STUDENT') {
      const [p] = await pool.query('SELECT preferred_area FROM student_profiles WHERE user_id=?', [u.id]);
      extra.preferredArea = p[0]?.preferred_area;
    }
    if (u.role === 'ROLE_OWNER') {
      const [p] = await pool.query('SELECT id,catering_name,verification_status FROM owner_profiles WHERE user_id=?', [u.id]);
      extra = {profileId: p[0]?.id, cateringName: p[0]?.catering_name, verificationStatus: p[0]?.verification_status};
    }
    ok(res, token(u, extra), 'Login successful!');
  } catch (e) { next(e); }
});

// ─── GEOCODING PROXY ───────────────────────────────────────────────────────
app.get('/api/geocode/reverse', async (req, res, next) => {
  try {
    const { lat, lon } = req.query;
    if (!lat || !lon) return fail(res, 400, 'lat and lon query parameters required');
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}&zoom=18&addressdetails=1`;
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'PartTimeJobPlatform/1.0', 'Accept-Language': 'en' }
    });
    if (!resp.ok) return fail(res, 502, 'Geocoding service unavailable');
    const data = await resp.json();
    ok(res, data);
  } catch (e) { next(e); }
});

// ─── JOBS ────────────────────────────────────────────────────────────────────

const jobSql = `SELECT j.*,o.catering_name,o.verification_status,u.id owner_user_id,u.full_name owner_name FROM catering_jobs j JOIN owner_profiles o ON o.id=j.owner_id JOIN users u ON u.id=o.user_id`;
const appSql = `SELECT a.*,j.title job_title,j.work_type,j.work_area,j.detailed_location,j.job_date,j.start_time,j.end_time,j.payment_type,j.is_on_spot_payment,j.contact_phone,j.contact_email,o.catering_name,o.verification_status,ou.id owner_user_id,ou.full_name owner_name,su.id student_user_id,su.full_name student_name,su.email student_email,su.phone student_phone,sp.college_name,sp.skills,sp.rating student_rating,sp.total_jobs_completed FROM job_applications a JOIN catering_jobs j ON j.id=a.job_id JOIN owner_profiles o ON o.id=j.owner_id JOIN users ou ON ou.id=o.user_id JOIN student_profiles sp ON sp.id=a.student_id JOIN users su ON su.id=sp.user_id`;

function job(r, unlocked = false) {
  return {
    id: r.id, title: r.title, description: r.description,
    workType: r.work_type, workTypeDisplayName: r.work_type,
    workArea: r.work_area, detailedLocation: unlocked ? r.detailed_location : undefined,
    jobDate: r.job_date, startTime: r.start_time, endTime: r.end_time,
    paymentAmount: r.payment_amount, paymentType: r.payment_type,
    paymentTypeDisplayName: r.payment_type, onSpotPayment: !!r.is_on_spot_payment,
    workersRequired: r.workers_required, workersSelected: r.workers_selected,
    requiredSkills: r.required_skills,
    contactPhone: unlocked ? r.contact_phone : undefined,
    contactEmail: unlocked ? r.contact_email : undefined,
    locationPhotoUrl: r.location_photo_url || null,
    latitude: r.latitude || null,
    longitude: r.longitude || null,
    locationAddress: r.location_address || null,
    applyDeadline: r.apply_deadline || null,
    status: r.status, ownerDecision: r.owner_decision || null, ownerDecisionAt: r.owner_decision_at || null, cateringName: r.catering_name,
    ownerId: r.owner_user_id,
    ownerVerified: r.verification_status === 'VERIFIED',
    createdAt: r.created_at
  };
}

function application(r, unlocked = false) {
  return {
    id: r.id, jobId: r.job_id, jobTitle: r.job_title,
    workType: r.work_type, workTypeDisplayName: r.work_type,
    workArea: r.work_area,
    detailedLocation: unlocked ? r.detailed_location : undefined,
    locationUnlocked: unlocked,
    jobDate: r.job_date, startTime: r.start_time, endTime: r.end_time,
    paymentType: r.payment_type, paymentTypeDisplayName: r.payment_type,
    onSpotPayment: !!r.is_on_spot_payment,
    contactPhone: unlocked ? r.contact_phone : undefined,
    contactEmail: unlocked ? r.contact_email : undefined,
    contactUnlocked: unlocked,
    ownerId: r.owner_user_id, cateringName: r.catering_name,
    ownerName: r.owner_name,
    ownerVerified: r.verification_status === 'VERIFIED',
    studentId: r.student_id, studentUserId: r.student_user_id,
    studentName: r.student_name, studentEmail: r.student_email,
    studentPhone: r.student_phone, collegeName: r.college_name,
    skills: r.skills, studentRating: r.student_rating,
    totalJobsCompleted: r.total_jobs_completed,
    status: r.status, attendanceStatus: r.attendance_status,
    workCompletionStatus: r.work_completion_status,
    paymentStatus: r.payment_status, paymentAmount: r.payment_amount,
    paymentConfirmationDate: r.payment_confirmation_date,
    notes: r.notes, appliedAt: r.applied_at,
    respondedAt: r.responded_at, createdAt: r.created_at
  };
}

function profile(r) {
  return r ? {
    id: r.id, userId: r.user_id, fullName: r.full_name,
    email: r.email, phone: r.phone,
    collegeName: r.college_name, preferredArea: r.preferred_area,
    skills: r.skills, bio: r.bio,
    emergencyContact: r.emergency_contact,
    profilePhotoUrl: r.profile_photo_url,
    totalJobsCompleted: r.total_jobs_completed, rating: r.rating,
    cateringName: r.catering_name,
    businessAddress: r.business_address,
    businessPhone: r.business_phone,
    verified: r.verification_status === 'VERIFIED',
    verificationStatus: r.verification_status,
    verifiedAt: r.verified_at,
    totalJobsPosted: r.total_jobs_posted,
    profilePhotoUrl: r.profile_photo_url
  } : null;
}

async function listJobs(req, res, next) {
  try {
    let sql = `${jobSql} WHERE j.status='OPEN' AND u.is_suspended=FALSE AND (j.apply_deadline IS NULL OR j.apply_deadline > NOW()) AND (j.owner_decision IS NULL OR j.owner_decision != 'REMOVED')`, v = [];
    const q = req.query;
    if (q.area || q.location) { sql += ' AND LOWER(j.work_area) LIKE LOWER(?)'; v.push(`%${q.area || q.location}%`); }
    if (q.workType) { sql += ' AND j.work_type=?'; v.push(q.workType); }
    if (q.jobDate) { sql += ' AND j.job_date=?'; v.push(q.jobDate); }
    if (q.minPayment) { sql += ' AND j.payment_amount>=?'; v.push(q.minPayment); }
    if (q.maxPayment) { sql += ' AND j.payment_amount<=?'; v.push(q.maxPayment); }
    if (q.paymentType) { sql += ' AND j.payment_type=?'; v.push(q.paymentType); }
    sql += ' ORDER BY j.job_date ASC,j.created_at DESC';
    const [r] = await pool.query(sql, v);
    ok(res, r.map(x => job(x)), 'Jobs retrieved successfully');
  } catch (e) { next(e); }
}

app.get('/api/public/google-maps-key', (req, res) => {
  const key = process.env.GOOGLE_MAPS_API_KEY || '';
  ok(res, {apiKey: key});
});

app.get('/api/public/jobs', listJobs);
app.get('/api/public/jobs/recommended', listJobs);

// Full jobs endpoint - returns jobs where all positions are filled
app.get('/api/public/jobs/full', async (req, res, next) => {
  try {
    let sql = `${jobSql} WHERE j.status IN ('OPEN','FILLED') AND j.workers_selected >= j.workers_required AND u.is_suspended=0`, v = [];
    const q = req.query;
    if (q.area || q.location) { sql += ' AND LOWER(j.work_area) LIKE LOWER(?)'; v.push(`%${q.area || q.location}%`); }
    if (q.workType) { sql += ' AND j.work_type=?'; v.push(q.workType); }
    sql += ' ORDER BY j.job_date DESC,j.created_at DESC';
    const [r] = await pool.query(sql, v);
    ok(res, r.map(x => ({...job(x), isFullyBooked: true})), 'Fully booked jobs retrieved');
  } catch (e) { next(e); }
});

app.get('/api/public/jobs/:id', async (req, res, next) => {
  try {
    const [r] = await pool.query(`${jobSql} WHERE j.id=?`, [req.params.id]);
    if (!r[0]) return fail(res, 404, 'Job not found');
    const j = job(r[0]);
    j.ownerName = r[0].owner_name;
    ok(res, j, 'Job details retrieved');
  } catch (e) { next(e); }
});

// ─── STUDENT ─────────────────────────────────────────────────────────────────

async function current(req, kind) {
  const table = kind === 'student' ? 'student_profiles' : 'owner_profiles';
  const [r] = await pool.query(`SELECT u.*,p.* FROM users u JOIN ${table} p ON p.user_id=u.id WHERE u.id=?`, [req.user.id]);
  return r[0];
}

app.get('/api/student/profile', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try { ok(res, profile(await current(req, 'student'))); } catch (e) { next(e); }
});

app.put('/api/student/profile', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const b = req.body;
    await transaction(async c => {
      await c.query('UPDATE users SET full_name=COALESCE(?,full_name),phone=COALESCE(?,phone) WHERE id=?', [b.fullName, b.phone, req.user.id]);
      await c.query('UPDATE student_profiles SET college_name=?,preferred_area=?,skills=?,bio=?,emergency_contact=?,profile_photo_url=COALESCE(?,profile_photo_url) WHERE user_id=?',
        [b.collegeName || null, b.preferredArea || null, b.skills || null, b.bio || null, b.emergencyContact || null, b.profilePhotoUrl || null, req.user.id]);
    });
    ok(res, profile(await current(req, 'student')), 'Profile updated successfully');
  } catch (e) { next(e); }
});

app.get('/api/student/dashboard', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`SELECT
      (SELECT COUNT(*) FROM catering_jobs WHERE status='OPEN') availableJobsCount,
      (SELECT COUNT(*) FROM job_applications a JOIN student_profiles s ON s.id=a.student_id WHERE s.user_id=?) totalApplicationsCount,
      (SELECT COUNT(*) FROM job_applications a JOIN student_profiles s ON s.id=a.student_id WHERE s.user_id=? AND a.status='ACCEPTED') acceptedApplicationsCount,
      (SELECT COUNT(*) FROM job_applications a JOIN student_profiles s ON s.id=a.student_id WHERE s.user_id=? AND a.status='APPLIED') appliedJobsCount,
      (SELECT COUNT(*) FROM job_applications a JOIN student_profiles s ON s.id=a.student_id WHERE s.user_id=? AND a.work_completion_status='COMPLETED') completedJobsCount,
      (SELECT COALESCE(SUM(amount),0) FROM payment_records p JOIN student_profiles s ON s.id=p.student_id WHERE s.user_id=? AND p.payment_status='PAID') totalEarnings,
      (SELECT COALESCE(SUM(amount),0) FROM payment_records p JOIN student_profiles s ON s.id=p.student_id WHERE s.user_id=? AND p.payment_status IN ('PENDING','INITIATED')) pendingEarnings,
      (SELECT COUNT(*) FROM notifications WHERE recipient_id=? AND is_read=FALSE) unreadNotificationsCount`,
      [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.id]);
    ok(res, r[0]);
  } catch (e) { next(e); }
});

app.get('/api/student/jobs', auth, guard('ROLE_STUDENT'), listJobs);

app.post('/api/student/jobs/:jobId/apply', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const data = await transaction(async c => {
      const [[s]] = await c.query('SELECT id FROM student_profiles WHERE user_id=?', [req.user.id]);
      const [[j]] = await c.query('SELECT * FROM catering_jobs WHERE id=? FOR UPDATE', [req.params.jobId]);
      if (!s || !j || j.status !== 'OPEN') throw Object.assign(new Error('Job is not available'), {status: 400});
      // Check if job is fully booked
      if (j.workers_selected >= j.workers_required) throw Object.assign(new Error('Applications are closed because all required workers have been hired.'), {status: 400});
      // Check application deadline
      if (j.apply_deadline) {
        const deadline = new Date(j.apply_deadline);
        if (new Date() > deadline) throw Object.assign(new Error('The application deadline for this job has passed.'), {status: 400});
      }
      const [x] = await c.query('INSERT INTO job_applications (job_id,student_id,payment_amount,notes) VALUES (?,?,?,?)',
        [j.id, s.id, j.payment_amount, req.body.notes || null]);
      const [r] = await c.query(`${appSql} WHERE a.id=?`, [x.insertId]);
      return application(r[0]);
    });
    ok(res, data, 'Application submitted successfully!');
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return fail(res, 409, 'You have already applied for this job');
    next(e);
  }
});

async function studentApps(req, res, next, filter = '') {
  try {
    const [r] = await pool.query(`${appSql} WHERE su.id=? ${filter} ORDER BY a.created_at DESC`, [req.user.id]);
    ok(res, r.map(x => application(x, x.status === 'ACCEPTED' || x.work_completion_status === 'COMPLETED')));
  } catch (e) { next(e); }
}

app.get('/api/student/applications', auth, guard('ROLE_STUDENT'), studentApps);
app.get('/api/student/applications/accepted', auth, guard('ROLE_STUDENT'), (q, s, n) => studentApps(q, s, n, "AND a.status='ACCEPTED'"));
app.get('/api/student/applications/completed', auth, guard('ROLE_STUDENT'), (q, s, n) => studentApps(q, s, n, "AND a.work_completion_status='COMPLETED'"));

app.delete('/api/student/applications/:id', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [r] = await pool.query("UPDATE job_applications a JOIN student_profiles s ON s.id=a.student_id SET a.status='CANCELLED' WHERE a.id=? AND s.user_id=? AND a.status='APPLIED'",
      [req.params.id, req.user.id]);
    if (!r.affectedRows) return fail(res, 400, 'Only pending applications can be cancelled');
    ok(res, null, 'Application cancelled successfully');
  } catch (e) { next(e); }
});

// ─── STUDENT CONFIRM RECEIPT (on-spot payment) ────────────────────────────
app.put('/api/student/applications/:id/confirm-payment', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const data = await transaction(async c => {
      // Find the application owned by this student
      const [[app]] = await c.query(
        `SELECT a.id, a.payment_status, a.status, p.id AS payment_id, p.payment_status AS pay_status, p.amount
         FROM job_applications a
         JOIN student_profiles s ON s.id = a.student_id
         LEFT JOIN payment_records p ON p.application_id = a.id
         WHERE a.id = ? AND s.user_id = ?`,
        [req.params.id, req.user.id]
      );
      if (!app) throw Object.assign(new Error('Application not found'), {status: 404});
      if (app.status !== 'ACCEPTED' && app.status !== 'COMPLETED')
        throw Object.assign(new Error('You can only confirm receipt for accepted or completed jobs'), {status: 400});
      if (app.pay_status === 'CONFIRMED')
        throw Object.assign(new Error('Payment has already been confirmed'), {status: 400});
      if (app.pay_status !== 'PAID' && app.pay_status !== 'PENDING')
        throw Object.assign(new Error('Payment is not in a confirmable state'), {status: 400});

      // Update payment_records: mark as CONFIRMED
      await c.query(
        "UPDATE payment_records SET payment_status='CONFIRMED', confirmed_paid_at=NOW(), notes=COALESCE(?,notes) WHERE id=?",
        [req.body.notes || null, app.payment_id]
      );

      // Update job_applications: confirm payment
      await c.query(
        "UPDATE job_applications SET payment_status='CONFIRMED', payment_confirmation_date=NOW() WHERE id=?",
        [app.id]
      );

      return {confirmed: true, amount: app.amount};
    });
    ok(res, data, 'Payment receipt confirmed successfully!');
  } catch (e) { next(e); }
});

// ─── STUDENT EARNINGS & TRANSACTION HISTORY ────────────────────────────────

// Get student earnings summary (total earned, pending, this month, etc.)
app.get('/api/student/earnings', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [[summary]] = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN payment_status='PAID' THEN amount ELSE 0 END), 0) totalEarned,
        COALESCE(SUM(CASE WHEN payment_status='PENDING' THEN amount ELSE 0 END), 0) pendingAmount,
        COALESCE(SUM(CASE WHEN payment_status='INITIATED' THEN amount ELSE 0 END), 0) processingAmount,
        COUNT(CASE WHEN payment_status='PAID' THEN 1 END) completedJobs,
        COUNT(CASE WHEN payment_status IN ('PENDING','INITIATED') THEN 1 END) pendingJobs,
        COALESCE(SUM(CASE WHEN payment_status='PAID' AND YEAR(marked_paid_at)=YEAR(NOW()) AND MONTH(marked_paid_at)=MONTH(NOW()) THEN amount ELSE 0 END), 0) thisMonthEarnings
      FROM payment_records p
      JOIN student_profiles sp ON sp.id=p.student_id
      WHERE sp.user_id=?
    `, [req.user.id]);
    ok(res, summary, 'Earnings summary retrieved');
  } catch (e) { next(e); }
});

// Get student transaction history (earnings/payments received)
app.get('/api/student/earnings/transactions', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const q = req.query;
    let sql = `SELECT p.*,j.id job_id,j.title job_title,j.work_area,j.job_date,j.work_type,
               u.full_name owner_name,o.catering_name,
               a.status application_status,a.work_completion_status
      FROM payment_records p
      JOIN catering_jobs j ON j.id=p.job_id
      JOIN owner_profiles o ON o.id=p.owner_id
      JOIN users u ON u.id=o.user_id
      JOIN job_applications a ON a.id=p.application_id
      JOIN student_profiles sp ON sp.id=p.student_id
      WHERE sp.user_id=?`, 
      v = [req.user.id];
    
    if (q.status) { sql += ' AND p.payment_status=?'; v.push(q.status); }
    if (q.fromDate) { sql += ' AND DATE(p.marked_paid_at)>=?'; v.push(q.fromDate); }
    if (q.toDate) { sql += ' AND DATE(p.marked_paid_at)<=?'; v.push(q.toDate); }
    if (q.minAmount) { sql += ' AND p.amount>=?'; v.push(q.minAmount); }
    if (q.maxAmount) { sql += ' AND p.amount<=?'; v.push(q.maxAmount); }
    
    sql += ' ORDER BY p.marked_paid_at DESC LIMIT 100';
    const [r] = await pool.query(sql, v);
    
    ok(res, r.map(x => ({
      id: x.id, applicationId: x.application_id, jobId: x.job_id,
      amount: x.amount, paymentType: x.payment_type, paymentTypeDisplayName: x.payment_type,
      paymentStatus: x.payment_status,
      jobTitle: x.job_title, workArea: x.work_area, jobDate: x.job_date,
      workType: x.work_type, ownerName: x.owner_name, cateringName: x.catering_name,
      applicationStatus: x.application_status, workCompletionStatus: x.work_completion_status,
      initiatedAt: x.initiated_at, markedPaidAt: x.marked_paid_at, notes: x.notes,
      createdAt: x.created_at
    })), 'Transaction history retrieved');
  } catch (e) { next(e); }
});

// ─── OWNER ───────────────────────────────────────────────────────────────────

async function ownerId(req) {
  const [r] = await pool.query('SELECT id FROM owner_profiles WHERE user_id=?', [req.user.id]);
  return r[0]?.id;
}

app.get('/api/owner/dashboard', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const [r] = await pool.query(`SELECT
      (SELECT COUNT(*) FROM catering_jobs WHERE owner_id=? AND status='OPEN') totalActiveJobsCount,
      (SELECT COUNT(*) FROM catering_jobs WHERE owner_id=? AND status='COMPLETED') totalCompletedJobsCount,
      (SELECT COUNT(*) FROM job_applications a JOIN catering_jobs j ON j.id=a.job_id WHERE j.owner_id=? AND a.status='ACCEPTED') totalHiredCount,
      (SELECT COUNT(*) FROM job_applications a JOIN catering_jobs j ON j.id=a.job_id WHERE j.owner_id=? AND a.status='APPLIED') totalPendingApplications,
      (SELECT COUNT(*) FROM payment_records p WHERE p.owner_id=? AND p.payment_status='SUCCESS') totalSuccessTransactions,
      (SELECT COUNT(*) FROM payment_records p WHERE p.owner_id=? AND p.payment_status='FAILED') totalFailedTransactions,
      (SELECT COUNT(*) FROM payment_records p WHERE p.owner_id=? AND p.payment_status='CREATED') totalPendingTransactions,
      (SELECT COALESCE(SUM(p.amount),0) FROM payment_records p WHERE p.owner_id=? AND p.payment_status='SUCCESS') totalTestRevenue,
      (SELECT COUNT(*) FROM notifications WHERE recipient_id=? AND is_read=FALSE) unreadNotificationsCount`,
      [oid, oid, oid, oid, oid, oid, oid, oid, req.user.id]);
    ok(res, r[0]);
  } catch (e) { next(e); }
});

app.get('/api/owner/profile', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try { ok(res, profile(await current(req, 'owner'))); } catch (e) { next(e); }
});

app.put('/api/owner/profile', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const b = req.body;
    await transaction(async c => {
      await c.query('UPDATE users SET full_name=COALESCE(?,full_name),phone=COALESCE(?,phone) WHERE id=?', [b.fullName, b.phone, req.user.id]);
      await c.query('UPDATE owner_profiles SET catering_name=COALESCE(?,catering_name),business_address=?,business_phone=?,profile_photo_url=COALESCE(?,profile_photo_url) WHERE user_id=?',
        [b.cateringName, b.businessAddress || null, b.businessPhone || null, b.profilePhotoUrl || null, req.user.id]);
    });
    ok(res, profile(await current(req, 'owner')), 'Profile updated successfully');
  } catch (e) { next(e); }
});

app.post('/api/owner/jobs', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const b = req.body, id = await ownerId(req);
    // Validate location coordinates (required for new jobs)
    if (!b.latitude || !b.longitude) {
      return fail(res, 400, 'Please select the exact job location on Google Maps.');
    }
    const lat = Number(b.latitude), lng = Number(b.longitude);
    if (isNaN(lat) || lat < -90 || lat > 90 || isNaN(lng) || lng < -180 || lng > 180)
      return fail(res, 400, 'Invalid location coordinates. Latitude must be between -90 and 90, longitude between -180 and 180.');
    const [x] = await pool.query(`INSERT INTO catering_jobs (owner_id,title,description,work_type,work_area,detailed_location,job_date,start_time,end_time,payment_amount,payment_type,is_on_spot_payment,workers_required,required_skills,contact_phone,contact_email,location_photo_url,apply_deadline,latitude,longitude,location_address) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [id, b.title, b.description || null, b.workType, b.workArea, b.detailedLocation, b.jobDate, b.startTime, b.endTime, b.paymentAmount, b.paymentType, b.onSpotPayment !== false, b.workersRequired, b.requiredSkills || null, b.contactPhone, b.contactEmail || null, b.locationPhotoUrl || null, b.applyDeadline || null, b.latitude || null, b.longitude || null, b.locationAddress || null]);
    const [r] = await pool.query(`${jobSql} WHERE j.id=?`, [x.insertId]);
    ok(res, job(r[0], true), 'Job posted successfully!');
  } catch (e) { next(e); }
});

app.get('/api/owner/jobs', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const [r] = await pool.query(`${jobSql} WHERE j.owner_id=? ORDER BY j.created_at DESC`, [oid]);
    const jobIds = r.map(x => x.id);
    let acceptedMap = {};
    let cancellationMap = {};
    let applicationCountMap = {};
    if (jobIds.length > 0) {
      const placeholders = jobIds.map(() => '?').join(',');
      const [acceptedRows] = await pool.query(
        `SELECT job_id, COUNT(*) cnt FROM job_applications WHERE job_id IN (${placeholders}) AND status='ACCEPTED' GROUP BY job_id`,
        jobIds
      );
      acceptedRows.forEach(row => { acceptedMap[row.job_id] = row.cnt > 0; });

      const [delRows] = await pool.query(
        `SELECT job_id, COUNT(*) cnt FROM job_deletion_requests WHERE job_id IN (${placeholders}) AND status='PENDING' GROUP BY job_id`,
        jobIds
      );
      delRows.forEach(row => { cancellationMap[row.job_id] = row.cnt > 0; });

      const [appCountRows] = await pool.query(
        `SELECT job_id, COUNT(*) cnt FROM job_applications WHERE job_id IN (${placeholders}) GROUP BY job_id`,
        jobIds
      );
      appCountRows.forEach(row => { applicationCountMap[row.job_id] = row.cnt; });
    }
    // Compute canDelete per job based on 3 scenarios
    const now = new Date();
    ok(res, r.map(x => {
      const hasAccepted = !!acceptedMap[x.id];
      const hasPendingCancel = !!cancellationMap[x.id];
      const jobEnd = new Date(`${x.job_date}T${x.end_time || '23:59:59'}`);
      const timeCrossed = now > jobEnd;

      const deadlinePassed = !!(x.apply_deadline && new Date(x.apply_deadline) <= now);
      const isFull = x.workers_selected >= x.workers_required;
      const needsDecision = deadlinePassed && !isFull && !x.owner_decision;
      const canDelete = !hasAccepted || timeCrossed || deadlinePassed || hasPendingCancel || x.status === 'REMOVED';
      return {...job(x, true), canDelete, hasPendingDeletionRequest: hasPendingCancel, isFull, deadlinePassed, needsDecision, applicationCount: applicationCountMap[x.id] || 0};
    }));
  } catch (e) { next(e); }
});

app.get('/api/owner/jobs/closed', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    // Closed jobs = jobs where apply_deadline has passed OR status is CANCELLED/COMPLETED/FILLED
    const [r] = await pool.query(
      `${jobSql} WHERE j.owner_id=? AND (j.status IN ('CANCELLED','COMPLETED') OR (j.apply_deadline IS NOT NULL AND j.apply_deadline <= NOW())) ORDER BY j.updated_at DESC`,
      [oid]
    );
    if (r.length === 0) return ok(res, []);

    const jobIds = r.map(x => x.id);
    const placeholders = jobIds.map(() => '?').join(',');

    // Get all applicants for these jobs with their details
    const [apps] = await pool.query(
      `${appSql} WHERE j.id IN (${placeholders}) ORDER BY j.id, a.applied_at ASC`,
      jobIds
    );

    // Group applications by job
    const appsByJob = {};
    apps.forEach(a => {
      if (!appsByJob[a.job_id]) appsByJob[a.job_id] = [];
      appsByJob[a.job_id].push(application(a, true));
    });

    ok(res, r.map(x => {
      const j = job(x, true);
      j.applicants = appsByJob[x.id] || [];
      j.isDeadlinePassed = !!(x.apply_deadline && new Date(x.apply_deadline) <= new Date());
      return j;
    }));
  } catch (e) { next(e); }
});

app.get('/api/owner/jobs/:id', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`${jobSql} WHERE j.id=? AND j.owner_id=?`, [req.params.id, await ownerId(req)]);
    if (!r[0]) return fail(res, 404, 'Job not found');
    const [a] = await pool.query(`${appSql} WHERE j.id=?`, [req.params.id]);
    ok(res, {...job(r[0], true), applications: a.map(x => application(x, true))});
  } catch (e) { next(e); }
});

app.put('/api/owner/jobs/:id', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const b = req.body;
    // Validate location coordinates if provided
    if (b.latitude != null && b.longitude != null) {
      const lat = Number(b.latitude), lng = Number(b.longitude);
      if (isNaN(lat) || lat < -90 || lat > 90 || isNaN(lng) || lng < -180 || lng > 180)
        return fail(res, 400, 'Invalid location coordinates.');
    }
    await pool.query('UPDATE catering_jobs SET title=?,description=?,work_type=?,work_area=?,detailed_location=?,job_date=?,start_time=?,end_time=?,payment_amount=?,payment_type=?,is_on_spot_payment=?,workers_required=?,required_skills=?,contact_phone=?,contact_email=?,location_photo_url=?,apply_deadline=?,latitude=?,longitude=?,location_address=? WHERE id=? AND owner_id=?',
      [b.title, b.description, b.workType, b.workArea, b.detailedLocation, b.jobDate, b.startTime, b.endTime, b.paymentAmount, b.paymentType, b.onSpotPayment, b.workersRequired, b.requiredSkills, b.contactPhone, b.contactEmail, b.locationPhotoUrl || null, b.applyDeadline || null, b.latitude || null, b.longitude || null, b.locationAddress || null, req.params.id, await ownerId(req)]);
    const [r] = await pool.query(`${jobSql} WHERE j.id=?`, [req.params.id]);
    ok(res, job(r[0], true), 'Job updated successfully');
  } catch (e) { next(e); }
});

app.delete('/api/owner/jobs/:id', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const data = await transaction(async c => {
      // 1. Verify job exists and belongs to this owner
      const [[jobRow]] = await c.query('SELECT id, status, job_date, end_time FROM catering_jobs WHERE id=? AND owner_id=? FOR UPDATE', [req.params.id, oid]);
      if (!jobRow) throw Object.assign(new Error('Job not found'), {status: 404});

      // 2. Find all hired (ACCEPTED) students
      const [acceptedApps] = await c.query(
        `SELECT a.id, a.student_id, su.full_name student_name
         FROM job_applications a
         JOIN student_profiles sp ON sp.id=a.student_id
         JOIN users su ON su.id=sp.user_id
         WHERE a.job_id=? AND a.status='ACCEPTED'`,
        [jobRow.id]
      );

      if (acceptedApps.length === 0) {
        // CASE A: No student hired → delete immediately
        await c.query('DELETE FROM catering_jobs WHERE id=? AND owner_id=?', [jobRow.id, oid]);
        return {deleted: true};
      }

      // CASE B: Student(s) hired → check for existing pending request
      const [[existingPending]] = await c.query(
        "SELECT COUNT(*) cnt FROM job_deletion_requests WHERE job_id=? AND status='PENDING'",
        [jobRow.id]
      );
      if (existingPending.cnt > 0) {
        throw Object.assign(new Error('A deletion request is already waiting for the hired student(s) to respond.'), {status: 400});
      }

      // Create deletion request for EACH hired student
      for (const app of acceptedApps) {
        await c.query(
          'INSERT INTO job_deletion_requests (job_id, owner_id, student_id) VALUES (?,?,?)',
          [jobRow.id, oid, app.student_id]
        );
        // Notify the hired student
        await c.query(
          "INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
          [app.student_id, 'Job Deletion Request',
           `The owner wants to delete the job you were hired for. Do you want to approve this request?`,
           'JOB_DELETION_REQUEST', null]
        );
      }
      return {deleted: false, requestCreated: true, hiredStudentCount: acceptedApps.length};
    });
    if (data.deleted) {
      ok(res, data, 'Job deleted successfully');
    } else {
      ok(res, data, 'Deletion request sent to the hired student(s).');
    }
  } catch (e) { next(e); }
});

// ─── STUDENT JOB DELETION REQUESTS ──────────────────────────────────────────

app.get('/api/student/deletion-requests', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [[sp]] = await pool.query('SELECT id FROM student_profiles WHERE user_id=?', [req.user.id]);
    if (!sp) return ok(res, []);
    const [rows] = await pool.query(
      `SELECT dr.*, j.title job_title, j.work_area, j.job_date, j.start_time, j.end_time,
              o.catering_name, u.full_name owner_name
       FROM job_deletion_requests dr
       JOIN catering_jobs j ON j.id=dr.job_id
       JOIN owner_profiles o ON o.id=dr.owner_id
       JOIN users u ON u.id=o.user_id
       WHERE dr.student_id=?
       ORDER BY dr.created_at DESC`,
      [sp.id]
    );
    ok(res, rows.map(r => ({
      id: r.id, jobId: r.job_id, ownerId: r.owner_id,
      status: r.status, createdAt: r.created_at, respondedAt: r.responded_at,
      jobTitle: r.job_title, workArea: r.work_area,
      jobDate: r.job_date, startTime: r.start_time, endTime: r.end_time,
      cateringName: r.catering_name, ownerName: r.owner_name
    })));
  } catch (e) { next(e); }
});

app.post('/api/student/deletion-requests/:id/accept', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [[sp]] = await pool.query('SELECT id FROM student_profiles WHERE user_id=?', [req.user.id]);
    if (!sp) return fail(res, 404, 'Student profile not found');
    const data = await transaction(async c => {
      // 1. Verify request exists, belongs to this student, and is PENDING
      const [[reqRow]] = await c.query(
        'SELECT * FROM job_deletion_requests WHERE id=? AND student_id=? AND status=? FOR UPDATE',
        [req.params.id, sp.id, 'PENDING']
      );
      if (!reqRow) throw Object.assign(new Error('This deletion request is no longer available.'), {status: 404});

      // 2. Mark request as ACCEPTED
      await c.query("UPDATE job_deletion_requests SET status='ACCEPTED',responded_at=NOW() WHERE id=?", [reqRow.id]);

      // 3. Delete the job (CASCADE handles applications, payments, other deletion requests)
      await c.query('DELETE FROM catering_jobs WHERE id=?', [reqRow.job_id]);

      // 4. Notify the owner
      await c.query(
        "INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
        [reqRow.owner_id, 'Deletion Request Accepted',
         'The hired student accepted your job deletion request. The job has been deleted.',
         'JOB_DELETION_ACCEPTED', reqRow.id]
      );
    });
    ok(res, data, 'Request accepted. The job has been deleted.');
  } catch (e) { next(e); }
});

app.post('/api/student/deletion-requests/:id/reject', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [[sp]] = await pool.query('SELECT id FROM student_profiles WHERE user_id=?', [req.user.id]);
    if (!sp) return fail(res, 404, 'Student profile not found');
    const data = await transaction(async c => {
      // 1. Verify request exists, belongs to this student, and is PENDING
      const [[reqRow]] = await c.query(
        'SELECT * FROM job_deletion_requests WHERE id=? AND student_id=? AND status=? FOR UPDATE',
        [req.params.id, sp.id, 'PENDING']
      );
      if (!reqRow) throw Object.assign(new Error('This deletion request is no longer available.'), {status: 404});

      // 2. Mark as REJECTED
      await c.query("UPDATE job_deletion_requests SET status='REJECTED',responded_at=NOW() WHERE id=?", [reqRow.id]);

      // 3. Notify the owner
      await c.query(
        "INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
        [reqRow.owner_id, 'Deletion Request Rejected',
         'The hired student rejected your job deletion request. The job remains active.',
         'JOB_DELETION_REJECTED', reqRow.id]
      );
    });
    ok(res, data, 'Request rejected. The job remains active.');
  } catch (e) { next(e); }
});

app.get('/api/owner/jobs/:id/applications', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`${appSql} WHERE j.id=? AND j.owner_id=?`, [req.params.id, await ownerId(req)]);
    ok(res, r.map(x => application(x, true)));
  } catch (e) { next(e); }
});

async function appAction(req, res, next, accept) {
  try {
    const id = await ownerId(req);
    const data = await transaction(async c => {
      const [r] = await c.query(`${appSql} WHERE a.id=? AND j.owner_id=? FOR UPDATE`, [req.params.id, id]);
      const a = r[0];
      if (!a) throw Object.assign(new Error('Application not found'), {status: 404});
      if (accept) {
        const [[count]] = await c.query("SELECT COUNT(*) count FROM job_applications WHERE job_id=? AND status='ACCEPTED'", [a.job_id]);
        const [[j]] = await c.query('SELECT workers_required FROM catering_jobs WHERE id=?', [a.job_id]);
        if (count.count >= j.workers_required) throw Object.assign(new Error('Worker limit has been reached'), {status: 400});
        await c.query("UPDATE job_applications SET status='ACCEPTED',responded_at=NOW() WHERE id=?", [a.id]);
        await c.query("UPDATE catering_jobs SET workers_selected=workers_selected+1,status=IF(workers_selected+1>=workers_required,'FILLED','OPEN') WHERE id=?", [a.job_id]);
        await c.query('INSERT INTO payment_records (application_id,job_id,student_id,owner_id,amount,payment_type) SELECT a.id,a.job_id,a.student_id,?,a.payment_amount,j.payment_type FROM job_applications a JOIN catering_jobs j ON j.id=a.job_id WHERE a.id=?', [id, a.id]);
        await c.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
          [a.student_user_id, 'Application Accepted', `Your application for "${a.job_title}" was accepted. Check Accepted Shifts for venue and contact details.`, 'APPLICATION_ACCEPTED', a.id]);
      } else {
        await c.query("UPDATE job_applications SET status='REJECTED',responded_at=NOW() WHERE id=?", [a.id]);
        await c.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
          [a.student_user_id, 'Application Update', `Your application for "${a.job_title}" was not accepted.`, 'APPLICATION_REJECTED', a.id]);
      }
      const [x] = await c.query(`${appSql} WHERE a.id=?`, [a.id]);
      return application(x[0], true);
    });
    ok(res, data, accept ? 'Applicant accepted successfully!' : 'Applicant rejected.');
  } catch (e) { next(e); }
}

app.put('/api/owner/applications/:id/accept', auth, guard('ROLE_OWNER'), (q, s, n) => appAction(q, s, n, true));
app.put('/api/owner/applications/:id/reject', auth, guard('ROLE_OWNER'), (q, s, n) => appAction(q, s, n, false));

app.put('/api/owner/applications/:id/attendance', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    await pool.query('UPDATE job_applications a JOIN catering_jobs j ON j.id=a.job_id SET a.attendance_status=?,a.work_completion_status=? WHERE a.id=? AND j.owner_id=?',
      [req.body.attendanceStatus, req.body.workCompletionStatus || 'COMPLETED', req.params.id, await ownerId(req)]);
    ok(res, null, 'Attendance updated successfully');
  } catch (e) { next(e); }
});

app.put('/api/owner/jobs/:id/complete', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const id = await ownerId(req);
    await transaction(async c => {
      await c.query("UPDATE catering_jobs SET status='COMPLETED' WHERE id=? AND owner_id=?", [req.params.id, id]);
      await c.query("UPDATE job_applications SET work_completion_status='COMPLETED' WHERE job_id=? AND status='ACCEPTED'", [req.params.id]);
    });
    ok(res, null, 'Job marked as completed!');
  } catch (e) { next(e); }
});

// ─── OWNER PAYMENTS ──────────────────────────────────────────────────────────

// Get pending payments owner needs to make
app.get('/api/owner/payments/pending', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const [r] = await pool.query(`SELECT p.*,j.title job_title,j.work_area,j.work_type,j.job_date,
      su.full_name student_name,su.email student_email,su.phone student_phone,
      sp.college_name,sp.skills,sp.rating student_rating,sp.total_jobs_completed,
      a.status application_status,a.work_completion_status
      FROM payment_records p
      JOIN catering_jobs j ON j.id=p.job_id
      JOIN student_profiles sp ON sp.id=p.student_id
      JOIN users su ON su.id=sp.user_id
      JOIN job_applications a ON a.id=p.application_id
      WHERE p.owner_id=? AND p.payment_status IN ('PENDING','INITIATED')
      ORDER BY p.created_at ASC`, [oid]);
    ok(res, r.map(x => ({
      id: x.id, applicationId: x.application_id, jobId: x.job_id,
      amount: x.amount, paymentType: x.payment_type, paymentStatus: x.payment_status,
      jobTitle: x.job_title, workArea: x.work_area, workType: x.work_type, jobDate: x.job_date,
      studentName: x.student_name, studentEmail: x.student_email, studentPhone: x.student_phone,
      collegeName: x.college_name, skills: x.skills, studentRating: x.student_rating,
      totalJobsCompleted: x.total_jobs_completed,
      applicationStatus: x.application_status, workCompletionStatus: x.work_completion_status,
      createdAt: x.created_at
    })), 'Pending payments retrieved');
  } catch (e) { next(e); }
});

// Get payment summary for owner
app.get('/api/owner/payments/summary', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const [[summary]] = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN payment_status='PAID' THEN amount ELSE 0 END), 0) totalPaid,
        COALESCE(SUM(CASE WHEN payment_status IN ('PENDING','INITIATED') THEN amount ELSE 0 END), 0) totalPending,
        COUNT(CASE WHEN payment_status='PAID' THEN 1 END) completedPayments,
        COUNT(CASE WHEN payment_status IN ('PENDING','INITIATED') THEN 1 END) pendingPayments,
        COALESCE(SUM(CASE WHEN payment_status='PAID' AND YEAR(marked_paid_at)=YEAR(NOW()) AND MONTH(marked_paid_at)=MONTH(NOW()) THEN amount ELSE 0 END), 0) thisMonthPaid
      FROM payment_records p
      WHERE p.owner_id=?
    `, [oid]);
    ok(res, summary, 'Payment summary retrieved');
  } catch (e) { next(e); }
});

// Initiate payment (owner starts the payment process)
app.put('/api/owner/payments/:id/initiate', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const [r] = await pool.query("UPDATE payment_records SET payment_status='INITIATED',initiated_at=NOW() WHERE id=? AND owner_id=? AND payment_status='PENDING'",
      [req.params.id, oid]);
    if (!r.affectedRows) return fail(res, 400, 'Payment not found or already initiated');
    
    // Notify student
    const [[payment]] = await pool.query('SELECT student_id FROM payment_records WHERE id=?', [req.params.id]);
    await pool.query(
      "INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
      [payment.student_id, 'Payment Initiated', 'The owner has initiated your payment and will transfer it soon.', 'PAYMENT_INITIATED', req.params.id]
    );
    
    ok(res, null, 'Owner has initiated payment to student');
  } catch (e) { next(e); }
});

// Complete payment (owner marks as paid with details)
app.put('/api/owner/payments/:id/complete', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const b = req.body;
    const data = await transaction(async c => {
      const [[payment]] = await c.query('SELECT application_id, student_id FROM payment_records WHERE id=? AND owner_id=?',
        [req.params.id, oid]);
      if (!payment) throw Object.assign(new Error('Payment not found'), {status: 404});
      
      // Update payment record
      await c.query(
        "UPDATE payment_records SET payment_status='PAID',marked_paid_at=NOW(),payment_method=?,notes=? WHERE id=?",
        [b.paymentMethod || 'BANK_TRANSFER', b.notes || null, req.params.id]
      );
      
      // Update job application
      await c.query("UPDATE job_applications SET payment_status='PAID',payment_confirmation_date=NOW() WHERE id=?",
        [payment.application_id]
      );
      
      // Notify student of successful payment
      await c.query(
        "INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
        [payment.student_id, 'Payment Received', 'You have received payment from the owner for your work.', 'PAYMENT_COMPLETED', req.params.id]
      );
      
      return {paid: true};
    });
    
    ok(res, data, 'Payment to student has been recorded successfully!');
  } catch (e) { next(e); }
});

// Owner views all payments (with filters)
app.get('/api/owner/payments', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const q = req.query;
    let sql = `SELECT p.*,j.title job_title,j.work_area,su.full_name student_name,su.email student_email
      FROM payment_records p
      JOIN catering_jobs j ON j.id=p.job_id
      JOIN student_profiles s ON s.id=p.student_id
      JOIN users su ON su.id=s.user_id
      WHERE p.owner_id=?`, v = [oid];
    
    if (q.status) { sql += ' AND p.payment_status=?'; v.push(q.status); }
    if (q.fromDate) { sql += ' AND DATE(p.marked_paid_at)>=?'; v.push(q.fromDate); }
    if (q.toDate) { sql += ' AND DATE(p.marked_paid_at)<=?'; v.push(q.toDate); }
    if (q.minAmount) { sql += ' AND p.amount>=?'; v.push(q.minAmount); }
    if (q.maxAmount) { sql += ' AND p.amount<=?'; v.push(q.maxAmount); }
    
    sql += ' ORDER BY p.created_at DESC LIMIT 100';
    const [r] = await pool.query(sql, v);
    
    ok(res, r.map(x => ({
      id: x.id, applicationId: x.application_id, jobId: x.job_id,
      studentId: x.student_id, ownerId: x.owner_id,
      amount: x.amount, paymentType: x.payment_type,
      paymentTypeDisplayName: x.payment_type,
      paymentStatus: x.payment_status, paymentMethod: x.payment_method,
      initiatedAt: x.initiated_at, markedPaidAt: x.marked_paid_at,
      notes: x.notes, createdAt: x.created_at,
      jobTitle: x.job_title, workArea: x.work_area,
      studentName: x.student_name, studentEmail: x.student_email
    })));
  } catch (e) { next(e); }
});

app.get('/api/owner/complaints', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`SELECT r.*,j.title job_title,j.work_area,j.job_date,
      su.full_name student_name,su.email student_email,su.phone student_phone,
      sp.skills student_skills,sp.preferred_area student_area,
      a.status application_status,a.payment_status application_payment_status,a.payment_amount assigned_amount
      FROM reports r JOIN users su ON su.id=r.reporter_id
      LEFT JOIN student_profiles sp ON sp.user_id=su.id
      LEFT JOIN catering_jobs j ON j.id=r.job_id
      LEFT JOIN job_applications a ON a.id=r.application_id
      WHERE r.target_user_id=? ORDER BY r.created_at DESC`, [req.user.id]);
    ok(res, r.map(x => ({
      ...x,
      studentName: x.student_name, studentEmail: x.student_email,
      studentPhone: x.student_phone, studentSkills: x.student_skills,
      studentArea: x.student_area, jobTitle: x.job_title,
      workArea: x.work_area, jobDate: x.job_date,
      applicationStatus: x.application_status,
      applicationPaymentStatus: x.application_payment_status,
      assignedAmount: x.assigned_amount, reportType: x.report_type,
      expectedAmount: x.expected_amount, receivedAmount: x.received_amount,
      evidenceNotes: x.evidence_notes, adminRemarks: x.admin_remarks,
      createdAt: x.created_at
    })));
  } catch (e) { next(e); }
});


// ─── OWNER MARK PAYMENT PAID ────────────────────────────────────────────────
app.put('/api/owner/applications/:id/payment', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    await checkPaymentTiming(req.params.id);
    const b = req.body;
    const status = (b.status || 'PAID').toUpperCase();
    const data = await transaction(async c => {
      const [[app]] = await c.query(
        `SELECT a.id, a.job_id, a.student_id, a.payment_amount, j.title job_title, su.id student_user_id
         FROM job_applications a
         JOIN catering_jobs j ON j.id=a.job_id
         JOIN student_profiles sp ON sp.id=a.student_id
         JOIN users su ON su.id=sp.user_id
         WHERE a.id=? AND j.owner_id=?`,
        [req.params.id, oid]
      );
      if (!app) throw Object.assign(new Error('Application not found'), {status: 404});
      const [[existing]] = await c.query('SELECT id FROM payment_records WHERE application_id=?', [app.id]);
      if (existing) {
        await c.query("UPDATE payment_records SET payment_status=?, payment_method='ON_SPOT', marked_paid_at=datetime('now','localtime'), notes=? WHERE application_id=?",
          [status, b.notes || null, app.id]);
      } else {
        await c.query("INSERT INTO payment_records (application_id,job_id,student_id,owner_id,amount,payment_type,payment_status,payment_method,marked_paid_at,notes) VALUES (?,?,?,?,?,?,?,?,datetime('now','localtime'),?)",
          [app.id, app.job_id, app.student_id, oid, app.payment_amount, 'ON_SPOT', status, 'ON_SPOT', b.notes || null]);
      }
      await c.query("UPDATE job_applications SET payment_status=?, payment_confirmation_date=datetime('now','localtime') WHERE id=?",
        [status, app.id]);
      if (status === 'PAID') {
        await c.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
          [app.student_user_id, 'Payment Received', 'You have received payment of ₹' + app.payment_amount + ' for "' + app.job_title + '".', 'PAYMENT_COMPLETED', app.id]);
      }
      return {paid: true};
    });
    ok(res, data, 'Payment recorded successfully!');
  } catch (e) { next(e); }
});

// ─── STUDENT PAYMENTS LIST ──────────────────────────────────────────────────
app.get('/api/student/payments', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [r] = await pool.query(
      `SELECT p.*, j.title job_title, j.work_area, j.job_date, o.catering_name, u.full_name owner_name
       FROM payment_records p
       JOIN catering_jobs j ON j.id=p.job_id
       JOIN owner_profiles o ON o.id=p.owner_id
       JOIN users u ON u.id=o.user_id
       JOIN student_profiles sp ON sp.id=p.student_id
       WHERE sp.user_id=? ORDER BY p.created_at DESC`,
      [req.user.id]
    );
    ok(res, r.map(x => ({
      id: x.id, applicationId: x.application_id, jobId: x.job_id,
      amount: x.amount, paymentType: x.payment_type, paymentStatus: x.payment_status,
      jobTitle: x.job_title, workArea: x.work_area, jobDate: x.job_date,
      cateringName: x.catering_name, ownerName: x.owner_name,
      razorpayOrderId: x.razorpay_order_id, razorpayPaymentId: x.razorpay_payment_id,
      environment: x.environment, paymentMethod: x.payment_method,
      createdAt: x.created_at, confirmedPaidAt: x.confirmed_paid_at
    })), 'Payments retrieved');
  } catch (e) { next(e); }
});

// ─── ADMIN PAYMENTS ──────────────────────────────────────────────────────────

// Admin views all platform payments
app.get('/api/admin/payments', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const q = req.query;
    let sql = `SELECT p.*,j.title job_title,j.work_area,
      su.full_name student_name,su.email student_email,
      ou.full_name owner_name,ou.email owner_email,o.catering_name
      FROM payment_records p
      JOIN catering_jobs j ON j.id=p.job_id
      JOIN student_profiles sp ON sp.id=p.student_id
      JOIN users su ON su.id=sp.user_id
      JOIN owner_profiles o ON o.id=p.owner_id
      JOIN users ou ON ou.id=o.user_id
      WHERE 1=1`, v = [];
    
    if (q.status) { sql += ' AND p.payment_status=?'; v.push(q.status); }
    if (q.fromDate) { sql += ' AND DATE(p.marked_paid_at)>=?'; v.push(q.fromDate); }
    if (q.toDate) { sql += ' AND DATE(p.marked_paid_at)<=?'; v.push(q.toDate); }
    
    sql += ' ORDER BY p.created_at DESC LIMIT 200';
    const [r] = await pool.query(sql, v);
    
    ok(res, r.map(x => ({
      id: x.id, applicationId: x.application_id, jobId: x.job_id,
      amount: x.amount, paymentType: x.payment_type, paymentStatus: x.payment_status,
      jobTitle: x.job_title, workArea: x.work_area,
      studentName: x.student_name, studentEmail: x.student_email,
      ownerName: x.owner_name, ownerEmail: x.owner_email, cateringName: x.catering_name,
      markedPaidAt: x.marked_paid_at, createdAt: x.created_at
    })), 'All payments retrieved');
  } catch (e) { next(e); }
});

// Admin payment statistics
app.get('/api/admin/payments/stats', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const [[stats]] = await pool.query(`
      SELECT
        COALESCE(SUM(amount), 0) totalTransacted,
        COALESCE(SUM(CASE WHEN payment_status='PAID' THEN amount ELSE 0 END), 0) totalPaid,
        COALESCE(SUM(CASE WHEN payment_status IN ('PENDING','INITIATED') THEN amount ELSE 0 END), 0) totalPending,
        COUNT(*) totalTransactions,
        COUNT(CASE WHEN payment_status='PAID' THEN 1 END) completedTransactions,
        COUNT(DISTINCT owner_id) uniqueOwners,
        COUNT(DISTINCT student_id) uniqueStudents
      FROM payment_records
    `);
    ok(res, stats, 'Payment statistics retrieved');
  } catch (e) { next(e); }
});

// ─── ADMIN ───────────────────────────────────────────────────────────────────

app.get('/api/admin/dashboard', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`SELECT
      (SELECT COUNT(*) FROM student_profiles) totalStudentsCount,
      (SELECT COUNT(*) FROM owner_profiles) totalOwnersCount,
      (SELECT COUNT(*) FROM owner_profiles WHERE verification_status='VERIFIED') verifiedOwnersCount,
      (SELECT COUNT(*) FROM catering_jobs WHERE status IN ('OPEN','FILLED')) totalActiveJobsCount,
      (SELECT COUNT(*) FROM catering_jobs WHERE status='COMPLETED') totalCompletedJobsCount,
      (SELECT COUNT(*) FROM job_applications) totalApplicationsCount,
      (SELECT COUNT(*) FROM reports WHERE status='PENDING') pendingDisputesCount,
      (SELECT COUNT(*) FROM users WHERE is_suspended=TRUE) suspendedUsersCount,
      (SELECT COALESCE(SUM(amount),0) FROM payment_records WHERE payment_status='PAID') totalPaymentsPaid,
      (SELECT COALESCE(SUM(amount),0) FROM payment_records WHERE payment_status IN ('PENDING','INITIATED')) totalPaymentsPending,
      (SELECT COUNT(*) FROM payment_records WHERE payment_status='PAID') completedPaymentCount,
      (SELECT COUNT(*) FROM payment_records WHERE payment_status IN ('PENDING','INITIATED')) pendingPaymentCount`);
    ok(res, r[0]);
  } catch (e) { next(e); }
});

app.get('/api/admin/users', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`SELECT u.*,sp.college_name student_college_name,op.catering_name owner_catering_name
      FROM users u LEFT JOIN student_profiles sp ON sp.user_id=u.id
      LEFT JOIN owner_profiles op ON op.user_id=u.id ORDER BY u.created_at DESC`);
    ok(res, r.map(x => ({
      id: x.id, email: x.email, fullName: x.full_name, phone: x.phone,
      role: x.role, active: !!x.is_active, suspended: !!x.is_suspended,
      createdAt: x.created_at,
      collegeName: x.student_college_name || null,
      cateringName: x.owner_catering_name || null
    })));
  } catch (e) { next(e); }
});

async function adminProfiles(req, res, next, t) {
  try {
    const [r] = await pool.query(`SELECT u.*,p.* FROM users u JOIN ${t === 'student' ? 'student_profiles' : 'owner_profiles'} p ON p.user_id=u.id`);
    ok(res, r.map(profile));
  } catch (e) { next(e); }
}

app.get('/api/admin/students', auth, guard('ROLE_ADMIN'), (q, s, n) => adminProfiles(q, s, n, 'student'));
app.get('/api/admin/owners', auth, guard('ROLE_ADMIN'), (q, s, n) => adminProfiles(q, s, n, 'owner'));

app.put('/api/admin/owners/:id/verify', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const v = req.query.verified !== 'false';
    await pool.query('UPDATE owner_profiles SET verification_status=?,verified_at=? WHERE id=?',
      [v ? 'VERIFIED' : 'PENDING_VERIFICATION', v ? new Date().toISOString() : null, req.params.id]);
    const [r] = await pool.query('SELECT u.*,p.* FROM users u JOIN owner_profiles p ON p.user_id=u.id WHERE p.id=?', [req.params.id]);
    ok(res, profile(r[0]), v ? 'Owner verified successfully!' : 'Owner verification reverted to pending.');
  } catch (e) { next(e); }
});

app.put('/api/admin/users/:id/suspend', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const v = req.query.suspended === 'true';
    await pool.query('UPDATE users SET is_suspended=? WHERE id=? AND role<>"ROLE_ADMIN"', [v, req.params.id]);
    const [r] = await pool.query('SELECT * FROM users WHERE id=?', [req.params.id]);
    ok(res, r[0], v ? 'User suspended successfully' : 'User reactivated successfully');
  } catch (e) { next(e); }
});

app.get('/api/admin/jobs', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`${jobSql} ORDER BY j.created_at DESC`);
    ok(res, r.map(x => job(x, true)));
  } catch (e) { next(e); }
});

app.delete('/api/admin/jobs/:id', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    await pool.query("UPDATE catering_jobs SET status='CANCELLED' WHERE id=?", [req.params.id]);
    ok(res, null, 'Job deleted/cancelled by admin');
  } catch (e) { next(e); }
});

// ─── ADMIN TRANSACTIONS ──────────────────────────────────────────────────────

// Get all transactions with filters, search, and pagination
app.get('/api/admin/transactions', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const filters = {
      status: req.query.status,
      environment: req.query.environment || 'TEST',
      fromDate: req.query.fromDate,
      toDate: req.query.toDate,
      searchQuery: req.query.search,
      limit: req.query.limit || 50,
      offset: req.query.offset || 0
    };

    const result = await getTransactionsList(filters);
    ok(res, result, 'Transactions retrieved');
  } catch (e) { next(e); }
});

// Get transaction summary/statistics for admin dashboard
app.get('/api/admin/transactions/summary', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const summary = await getTransactionSummary({
      fromDate: req.query.fromDate,
      toDate: req.query.toDate
    });
    ok(res, summary, 'Transaction summary retrieved');
  } catch (e) { next(e); }
});

// Get transaction details by ID
app.get('/api/admin/transactions/:id', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const txn = await getTransactionDetails(req.params.id);
    if (!txn) return fail(res, 404, 'Transaction not found');
    ok(res, txn, 'Transaction details retrieved');
  } catch (e) { next(e); }
});

// Export transactions (admin only)
app.get('/api/admin/transactions/export/csv', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const filters = {
      status: req.query.status,
      environment: 'TEST',
      fromDate: req.query.fromDate,
      toDate: req.query.toDate
    };

    const {transactions} = await getTransactionsList({...filters, limit: 10000, offset: 0});

    // Build CSV
    const headers = ['Transaction ID', 'Student', 'Owner', 'Job', 'Amount', 'Status', 'Environment', 'Payment Method', 'Order ID', 'Payment ID', 'Created Date'];
    const rows = transactions.map(t => [
      t.transactionId,
      t.studentName,
      t.ownerName,
      t.jobTitle,
      `₹${t.amount}`,
      t.paymentStatus,
      t.environment,
      t.paymentMethod || 'N/A',
      t.razorpayOrderId || '',
      t.razorpayPaymentId || '',
      new Date(t.createdAt).toLocaleString('en-IN')
    ]);

    const csv = [headers, ...rows].map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="transactions.csv"');
    res.send(csv);
  } catch (e) { next(e); }
});

// ─── STUDENT TRANSACTIONS ───────────────────────────────────────────────────

// Get student's own transactions
app.get('/api/student/transactions', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [[studentProfile]] = await pool.query('SELECT id FROM student_profiles WHERE user_id=?', [req.user.id]);
    if (!studentProfile) return fail(res, 404, 'Student profile not found');

    const filters = {
      studentId: studentProfile.id,
      status: req.query.status,
      environment: 'TEST',
      limit: req.query.limit || 20,
      offset: req.query.offset || 0
    };

    const result = await getTransactionsList(filters);
    ok(res, result, 'Student transactions retrieved');
  } catch (e) { next(e); }
});

// Get student transaction details
app.get('/api/student/transactions/:id', auth, guard('ROLE_STUDENT'), async (req, res, next) => {
  try {
    const [[studentProfile]] = await pool.query('SELECT id FROM student_profiles WHERE user_id=?', [req.user.id]);
    if (!studentProfile) return fail(res, 404, 'Student profile not found');

    const txn = await getTransactionDetails(req.params.id);
    if (!txn) return fail(res, 404, 'Transaction not found');
    
    // Verify student owns this transaction
    if (txn.studentId !== studentProfile.id) {
      return fail(res, 403, 'You do not have permission to view this transaction');
    }

    ok(res, txn, 'Transaction details retrieved');
  } catch (e) { next(e); }
});

// ─── OWNER TRANSACTIONS ─────────────────────────────────────────────────────

// Get owner's transactions (from their jobs)
app.get('/api/owner/transactions', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const [[ownerProfile]] = await pool.query('SELECT id FROM owner_profiles WHERE user_id=?', [req.user.id]);
    if (!ownerProfile) return fail(res, 404, 'Owner profile not found');

    const filters = {
      ownerId: ownerProfile.id,
      status: req.query.status,
      environment: 'TEST',
      limit: req.query.limit || 20,
      offset: req.query.offset || 0
    };

    const result = await getTransactionsList(filters);
    ok(res, result, 'Owner transactions retrieved');
  } catch (e) { next(e); }
});

// Get owner transaction details
app.get('/api/owner/transactions/:id', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const [[ownerProfile]] = await pool.query('SELECT id FROM owner_profiles WHERE user_id=?', [req.user.id]);
    if (!ownerProfile) return fail(res, 404, 'Owner profile not found');

    const txn = await getTransactionDetails(req.params.id);
    if (!txn) return fail(res, 404, 'Transaction not found');
    
    // Verify owner owns the job in this transaction
    if (txn.ownerId !== ownerProfile.id) {
      return fail(res, 403, 'You do not have permission to view this transaction');
    }

    ok(res, txn, 'Transaction details retrieved');
  } catch (e) { next(e); }
});

// ─── NOTIFICATIONS ───────────────────────────────────────────────────────────

app.get('/api/notifications', auth, async (req, res, next) => {
  try {
    const [r] = await pool.query('SELECT * FROM notifications WHERE recipient_id=? ORDER BY created_at DESC', [req.user.id]);
    ok(res, r.map(x => ({...x, isRead: !!x.is_read})));
  } catch (e) { next(e); }
});

app.get('/api/notifications/unread-count', auth, async (req, res, next) => {
  try {
    const [r] = await pool.query('SELECT COUNT(*) count FROM notifications WHERE recipient_id=? AND is_read=FALSE', [req.user.id]);
    ok(res, r[0].count);
  } catch (e) { next(e); }
});

app.put('/api/notifications/:id/read', auth, async (req, res, next) => {
  try {
    await pool.query('UPDATE notifications SET is_read=TRUE WHERE id=? AND recipient_id=?', [req.params.id, req.user.id]);
    ok(res, null, 'Notification marked as read');
  } catch (e) { next(e); }
});

app.put('/api/notifications/read-all', auth, async (req, res, next) => {
  try {
    await pool.query('UPDATE notifications SET is_read=TRUE WHERE recipient_id=?', [req.user.id]);
    ok(res, null, 'All notifications marked as read');
  } catch (e) { next(e); }
});

// ─── REPORTS / COMPLAINTS ───────────────────────────────────────────────────

app.post('/api/reports', auth, async (req, res, next) => {
  try {
    const b = req.body;
    const result = await transaction(async c => {
      const [[target]] = await c.query('SELECT ou.id owner_user_id,j.title FROM job_applications a JOIN student_profiles sp ON sp.id=a.student_id JOIN catering_jobs j ON j.id=a.job_id JOIN owner_profiles op ON op.id=j.owner_id JOIN users ou ON ou.id=op.user_id WHERE a.id=? AND sp.user_id=?',
        [b.applicationId, req.user.id]);
      if (!target) throw Object.assign(new Error('Application not found or not owned by student'), {status: 404});
      const [created] = await c.query('INSERT INTO reports (reporter_id,target_user_id,job_id,application_id,report_type,description,expected_amount,received_amount,evidence_notes) VALUES (?,?,?,?,?,?,?,?,?)',
        [req.user.id, target.owner_user_id, b.jobId || null, b.applicationId || null, b.reportType, b.description, b.expectedAmount || null, b.receivedAmount || null, b.evidenceNotes || null]);
      await c.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
        [target.owner_user_id, 'Student Complaint Received', `A student submitted a complaint about "${target.title}". Please review it and cooperate with platform administrators.`, 'REPORT_SUBMITTED', created.insertId]);
      return created.insertId;
    });
    ok(res, {id: result}, 'Report submitted to the owner and platform administrators.');
  } catch (e) { next(e); }
});

app.get('/api/reports/my-reports', auth, async (req, res, next) => {
  try {
    const [r] = await pool.query('SELECT * FROM reports WHERE reporter_id=?', [req.user.id]);
    ok(res, r);
  } catch (e) { next(e); }
});

// FIXED: Admin reports endpoint now includes target user details (name, email, catering name)
app.get('/api/admin/reports', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    const [r] = await pool.query(`SELECT r.*,
      u.full_name reporter_name, u.email reporter_email,
      tu.full_name target_user_name, tu.email target_user_email,
      op.catering_name target_catering_name
      FROM reports r
      JOIN users u ON u.id=r.reporter_id
      JOIN users tu ON tu.id=r.target_user_id
      LEFT JOIN owner_profiles op ON op.user_id=tu.id
      ORDER BY r.created_at DESC`);
    ok(res, r.map(x => ({
      ...x,
      reporterName: x.reporter_name,
      reporterEmail: x.reporter_email,
      targetUserName: x.target_user_name,
      targetUserEmail: x.target_user_email,
      targetCateringName: x.target_catering_name,
      reportTypeDisplayName: x.report_type
    })));
  } catch (e) { next(e); }
});

app.put('/api/admin/reports/:id/resolve', auth, guard('ROLE_ADMIN'), async (req, res, next) => {
  try {
    await pool.query('UPDATE reports SET status=?,admin_remarks=?,resolved_at=NOW() WHERE id=?',
      [req.body.status, req.body.adminRemarks || null, req.params.id]);
    const [r] = await pool.query('SELECT * FROM reports WHERE id=?', [req.params.id]);
    ok(res, r[0], 'Report resolved successfully');
  } catch (e) { next(e); }
});

app.delete('/api/reports/:id', auth, async (req, res, next) => {
  try {
    const result = await transaction(async c => {
      const [[report]] = await c.query('SELECT id,target_user_id FROM reports WHERE id=? AND reporter_id=? FOR UPDATE',
        [req.params.id, req.user.id]);
      if (!report) throw Object.assign(new Error('Complaint not found'), {status: 404});
      await c.query('DELETE FROM reports WHERE id=? AND reporter_id=?', [req.params.id, req.user.id]);
      await c.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
        [report.target_user_id, 'Complaint Withdrawn', 'The student withdrew the complaint. It has been removed from your complaints list.', 'REPORT_WITHDRAWN', report.id]);
      return report.id;
    });
    ok(res, {id: result}, 'Complaint withdrawn successfully.');
  } catch (e) { next(e); }
});

// ─── FILE UPLOAD ─────────────────────────────────────────────────────────────

app.post('/api/upload/image', auth, upload.single('image'), (req, res, next) => {
  try {
    if (!req.file) {
      console.error('[UPLOAD] No file received. Body keys:', Object.keys(req.body || {}));
      return fail(res, 400, 'No image file uploaded. Please select an image file under 5MB.');
    }
    const url = `/uploads/${req.file.filename}`;
    console.log('[UPLOAD] File saved:', req.file.filename, 'URL:', url);
    ok(res, {url}, 'Image uploaded successfully');
  } catch (e) {
    console.error('[UPLOAD] Error:', e.message);
    next(e);
  }
});
// Multer + general error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('[UPLOAD] Multer error:', err.code, err.message);
    if (err.code === 'LIMIT_FILE_SIZE') return fail(res, 400, 'File too large. Maximum size is 5MB.');
    return fail(res, 400, 'Upload failed: ' + err.message);
  }
  if (err.message && err.message.includes('image')) {
    console.error('[UPLOAD] Image filter error:', err.message);
    return fail(res, 400, err.message);
  }
  next(err);
});

// ─── FORGOT PASSWORD ───────────────────────────────────────────────────────

const resetChallenges = new Map();

app.post('/api/auth/forgot-password', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Enter a valid email address');
    const [r] = await pool.query('SELECT id, email FROM users WHERE email=?', [email]);
    if (!r[0]) return fail(res, 404, 'No account found with that email');
    const id = crypto.randomUUID();
    const code = String(crypto.randomInt(100000, 1000000));
    await sendEmailOtp(email, code);
    resetChallenges.set(id, {email, code, expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0});
    ok(res, {verificationId: id, expiresInSeconds: 600}, 'Password reset code sent to your email');
  } catch (e) { next(e); }
});

app.post('/api/auth/forgot-password/verify', async (req, res, next) => {
  try {
    const challenge = resetChallenges.get(req.body.verificationId);
    const otp = String(req.body.otp || '');
    if (!challenge || challenge.expiresAt < Date.now()) return fail(res, 400, 'Request a new reset code');
    if (!/^\d{6}$/.test(otp)) return fail(res, 400, 'OTP must contain exactly 6 digits');
    if (challenge.attempts >= 5) return fail(res, 429, 'Too many incorrect codes. Request a new code');
    if (otp !== challenge.code) { challenge.attempts++; return fail(res, 400, 'Incorrect verification code'); }
    challenge.verified = true;
    ok(res, null, 'Email verified successfully');
  } catch (e) { next(e); }
});

app.post('/api/auth/forgot-password/reset', async (req, res, next) => {
  try {
    const challenge = resetChallenges.get(req.body.verificationId);
    if (!challenge || !challenge.verified) return fail(res, 400, 'Please verify your email first');
    const newPassword = String(req.body.password || '');
    if (!newPassword || newPassword.length < 6) return fail(res, 400, 'Password must be at least 6 characters');
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash=? WHERE email=?', [hash, challenge.email]);
    resetChallenges.delete(req.body.verificationId);
    ok(res, null, 'Password reset successful! You can now sign in with your new password.');
  } catch (e) { next(e); }
});

// ─── DELETE ACCOUNT ─────────────────────────────────────────────────────────

app.delete('/api/account', auth, async (req, res, next) => {
  try {
    const password = String(req.body.password || '');
    if (!password) return fail(res, 400, 'Password is required to delete your account');
    const [r] = await pool.query('SELECT id, password_hash FROM users WHERE id=?', [req.user.id]);
    if (!r[0] || !(await bcrypt.compare(password, r[0].password_hash)))
      return fail(res, 401, 'Incorrect password');
    // Delete user (cascading deletes handle profiles, jobs, applications, etc.)
    await pool.query('DELETE FROM users WHERE id=? AND role<>"ROLE_ADMIN"', [req.user.id]);
    ok(res, null, 'Account deleted successfully');
  } catch (e) { next(e); }
});

// ─── STATIC FILES & ERROR HANDLING ───────────────────────────────────────────


// ─── JOB LIFECYCLE: DEADLINE DETECTION ──────────────────────────────────────

async function detectDeadlinePassedJobs() {
  try {
    const [jobs] = await pool.query(
      "SELECT j.id, j.owner_id, j.title, j.workers_required, j.workers_selected, j.apply_deadline, u.id owner_user_id FROM catering_jobs j JOIN owner_profiles o ON o.id=j.owner_id JOIN users u ON u.id=o.user_id WHERE j.status='OPEN' AND j.apply_deadline IS NOT NULL AND j.apply_deadline <= datetime('now','localtime') AND j.workers_selected < j.workers_required AND (j.owner_decision IS NULL OR j.owner_decision != 'CONTINUE')"
    );
    for (const j of jobs) {
      const [[existingNotif]] = await pool.query(
        "SELECT id FROM notifications WHERE recipient_id=? AND type='DEADLINE_REACHED' AND related_entity_id=? AND created_at > datetime('now','-1 day','localtime')",
        [j.owner_user_id, j.id]
      );
      if (!existingNotif) {
        await pool.query(
          "INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)",
          [j.owner_user_id, 'Application Deadline Reached',
           'Your job has not received all required workers (' + j.workers_selected + '/' + j.workers_required + '). Please choose whether to continue or remove the job.',
           'DEADLINE_REACHED', j.id]
        );
      }
    }
  } catch (e) {
    console.error('[LIFECYCLE] Deadline detection error:', e.message);
  }
}
setInterval(detectDeadlinePassedJobs, 5 * 60 * 1000);

app.put('/api/owner/jobs/:id/decision', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const { decision } = req.body;
    if (!decision || !['CONTINUE', 'REMOVE'].includes(decision.toUpperCase())) {
      return fail(res, 400, 'Decision must be CONTINUE or REMOVE');
    }
    const [[jobRec]] = await pool.query('SELECT * FROM catering_jobs WHERE id=? AND owner_id=?', [req.params.id, oid]);
    if (!jobRec) return fail(res, 404, 'Job not found');
    const now = new Date().toISOString();
    if (decision.toUpperCase() === 'CONTINUE') {
      await pool.query("UPDATE catering_jobs SET owner_decision='CONTINUE', owner_decision_at=? WHERE id=?", [now, req.params.id]);
      const [acceptedApps] = await pool.query("SELECT su.id student_user_id FROM job_applications a JOIN student_profiles sp ON sp.id=a.student_id JOIN users su ON su.id=sp.user_id WHERE a.job_id=? AND a.status='ACCEPTED'", [req.params.id]);
      for (const app of acceptedApps) {
        await pool.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)", [app.student_user_id, 'Job Confirmed', 'The owner confirmed the job will proceed.', 'JOB_CONTINUED', jobRec.id]);
      }
      ok(res, null, 'Job continued successfully');
    } else {
      await pool.query("UPDATE catering_jobs SET owner_decision='REMOVED', owner_decision_at=?, status='REMOVED' WHERE id=?", [now, req.params.id]);
      await pool.query("UPDATE job_applications SET status='CANCELLED' WHERE job_id=? AND status='APPLIED'", [req.params.id]);
      const [pendingApps] = await pool.query("SELECT su.id student_user_id FROM job_applications a JOIN student_profiles sp ON sp.id=a.student_id JOIN users su ON su.id=sp.user_id WHERE a.job_id=?", [req.params.id]);
      for (const app of pendingApps) {
        await pool.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)", [app.student_user_id, 'Job Removed', 'The job has been removed by the owner.', 'JOB_REMOVED', jobRec.id]);
      }
      ok(res, null, 'Job removed successfully');
    }
  } catch (e) { next(e); }
});

app.put('/api/owner/jobs/:id/remove', auth, guard('ROLE_OWNER'), async (req, res, next) => {
  try {
    const oid = await ownerId(req);
    const [[jobRec]] = await pool.query('SELECT * FROM catering_jobs WHERE id=? AND owner_id=?', [req.params.id, oid]);
    if (!jobRec) return fail(res, 404, 'Job not found');
    if (jobRec.status === 'REMOVED') return fail(res, 400, 'Job is already removed');
    const now = new Date().toISOString();
    await pool.query("UPDATE catering_jobs SET owner_decision='REMOVED', owner_decision_at=?, status='REMOVED' WHERE id=?", [now, req.params.id]);
    await pool.query("UPDATE job_applications SET status='CANCELLED' WHERE job_id=? AND status='APPLIED'", [req.params.id]);
    const [allApps] = await pool.query("SELECT su.id student_user_id FROM job_applications a JOIN student_profiles sp ON sp.id=a.student_id JOIN users su ON su.id=sp.user_id WHERE a.job_id=?", [req.params.id]);
    for (const app of allApps) {
      await pool.query("INSERT INTO notifications (recipient_id,title,message,type,related_entity_id) VALUES (?,?,?,?,?)", [app.student_user_id, 'Job Removed', 'The job has been removed by the owner.', 'JOB_REMOVED', jobRec.id]);
    }
    ok(res, null, 'Job removed successfully');
  } catch (e) { next(e); }
});

async function checkPaymentTiming(applicationId) {
  const [[app]] = await pool.query('SELECT j.job_date, j.end_time, a.status FROM job_applications a JOIN catering_jobs j ON j.id=a.job_id WHERE a.id=?', [applicationId]);
  if (!app) throw Object.assign(new Error('Application not found'), {status: 404});
  const jobDateTime = new Date(app.job_date + 'T' + (app.end_time || '23:59:59'));
  const paymentAvailableAt = new Date(jobDateTime.getTime() - 60 * 60 * 1000);
  if (new Date() < paymentAvailableAt) {
    throw Object.assign(new Error('Payment is not available yet. It becomes available 1 hour before job completion.'), {status: 400});
  }
  return true;
}

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(staticDir));
// Wire up Razorpay routes (some require auth, some don't - handled in routes)
app.use('/', razorpayRouter);
// Razorpay webhook needs raw body - mount before JSON parser for this specific route  
app.post('/api/razorpay/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
  try {
    if (webhookSecret) {
      const signature = req.headers['x-razorpay-signature'];
      const body = typeof req.body === 'string' ? req.body : req.body.toString();
      const expectedSig = crypto.createHmac('sha256', webhookSecret).update(body).digest('hex');
      if (signature !== expectedSig) return res.status(400).json({message: 'Invalid signature'});
    }
    const event = JSON.parse(typeof req.body === 'string' ? req.body : req.body.toString());
    console.log('[RAZORPAY] Webhook:', event.event);
    if (event.event === 'payment.captured') {
      const p = event.payload.payment.entity;
      const [[rec]] = await pool.query("SELECT * FROM payment_records WHERE razorpay_order_id=? AND payment_status!='SUCCESS' LIMIT 1", [p.order_id]);
      if (rec) {
        await transaction(async c => {
          await c.query("UPDATE payment_records SET razorpay_payment_id=COALESCE(?,razorpay_payment_id),payment_status='SUCCESS',payment_method=?,confirmed_paid_at=NOW() WHERE id=? AND payment_status!='SUCCESS'", [p.id, p.method, rec.id]);
          await c.query("UPDATE job_applications SET payment_status='SUCCESS',payment_confirmation_date=NOW() WHERE id=? AND payment_status!='SUCCESS'", [rec.application_id]);
        });
      }
    } else if (event.event === 'payment.failed') {
      const p = event.payload.payment.entity;
      const failReason = p.error_description || p.error_reason || null;
      await pool.query("UPDATE payment_records SET payment_status='FAILED', failure_reason=? WHERE razorpay_order_id=? AND payment_status='CREATED'", [failReason, p.order_id]);
    } else if (event.event === 'refund.created' || event.event === 'refund.processed') {
      const r = event.payload.refund.entity;
      if (r.payment_id) {
        await pool.query("UPDATE payment_records SET payment_status='REFUNDED' WHERE razorpay_payment_id=? AND payment_status IN ('SUCCESS','CONFIRMED')", [r.payment_id]);
        console.log('[RAZORPAY] Webhook: refund processed for payment', r.payment_id);
      }
    }
    res.json({status: 'ok'});
  } catch (e) { console.error('[RAZORPAY] Webhook error:', e.message); res.json({status: 'ok'}); }
});
app.get('*', (req, res) => res.sendFile(path.join(staticDir, 'index.html')));
app.use((e, req, res, next) => { console.error(e); fail(res, e.status || 500, e.status ? e.message : 'Internal server error'); });

// ─── START ───────────────────────────────────────────────────────────────────

if (require.main === module) {
  initializeDatabase().then(() => app.listen(PORT, '0.0.0.0', () => console.log(`PartTime Job Platform listening on http://0.0.0.0:${PORT}`)))
    .catch(e => { console.error('Database initialization failed:', e.message); process.exitCode = 1; });
}

module.exports = app;
