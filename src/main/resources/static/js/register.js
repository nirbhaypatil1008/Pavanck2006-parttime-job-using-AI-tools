/**
 * PARTTIME JOB PLATFORM — MULTI-STEP REGISTRATION WIZARD
 * Frontend controller for the registration flow.
 */

const RegWizard = {
  _role: null,
  _token: null,
  _phoneTimer: null,
  _emailTimer: null,
  _phoneCooldown: 0,
  _emailCooldown: 0,

  // ─── Step Navigation ─────────────────────────────────────────────────────

  goToStep(step) {
    document.querySelectorAll('.reg-step').forEach(s => s.classList.remove('active'));
    document.getElementById('step' + step)?.classList.add('active');

    // Update progress dots
    for (let i = 1; i <= 5; i++) {
      const dot = document.getElementById('dot' + i);
      const line = document.getElementById('line' + (i - 1));
      dot.classList.remove('active', 'done');
      if (i < step) { dot.classList.add('done'); dot.innerHTML = '<i class="bi bi-check-lg"></i>'; }
      else if (i === step) { dot.classList.add('active'); dot.textContent = i; }
      else { dot.textContent = i; }
      if (line) { line.classList.toggle('done', i < step); }
    }

    // Update step labels
    const labels = document.querySelectorAll('.reg-step-label');
    labels.forEach((l, i) => l.classList.toggle('active', i + 1 === step));

    window.scrollTo({ top: 0, behavior: 'smooth' });
  },

  // ─── Step 1: Account Type ───────────────────────────────────────────────

  selectType(role) {
    this._role = role;
    document.getElementById('typeStudent').classList.toggle('selected', role === 'ROLE_STUDENT');
    document.getElementById('typeOwner').classList.toggle('selected', role === 'ROLE_OWNER');
    document.getElementById('studentFields').style.display = role === 'ROLE_STUDENT' ? 'block' : 'none';
    document.getElementById('ownerFields').style.display = role === 'ROLE_OWNER' ? 'block' : 'none';
    document.getElementById('step2Title').textContent = role === 'ROLE_STUDENT' ? 'Student Information' : 'Owner Information';

    setTimeout(() => this.goToStep(2), 200);
  },

  // ─── Step 2: Submit Info ────────────────────────────────────────────────

  async submitInfo(e) {
    e.preventDefault();
    if (!this._role) { showToast('Please select an account type', 'warning'); return false; }

    const password = document.getElementById('regPassword').value;
    const confirm = document.getElementById('regConfirmPassword').value;
    if (password !== confirm) {
      const err = document.getElementById('regPassError');
      err.textContent = 'Passwords do not match';
      err.style.display = 'block';
      return false;
    }
    document.getElementById('regPassError').style.display = 'none';

    const phone = document.getElementById('regPhone').value.trim();
    const digitsOnly = phone.replace(/[\s\-()+]/g, '');
    if (!/^\+?[\d\s-]{7,20}$/.test(phone) || !/^\d{8,15}$/.test(digitsOnly)) {
      const err = document.getElementById('regPhoneError');
      err.textContent = 'Enter a valid phone number — e.g. 9876543210 or +91 9876543210';
      err.style.display = 'block';
      return false;
    }
    document.getElementById('regPhoneError').style.display = 'none';

    const btn = document.getElementById('regInfoSubmitBtn');
    const payload = {
      role: this._role,
      fullName: document.getElementById('regFullName').value.trim(),
      email: document.getElementById('regEmail').value.trim(),
      phone: phone,
      password: password
    };

    if (this._role === 'ROLE_STUDENT') {
      payload.collegeName = document.getElementById('regCollegeName')?.value.trim();
      payload.preferredArea = document.getElementById('regPrefArea')?.value.trim();
      payload.skills = document.getElementById('regSkills')?.value.trim();
    } else {
      payload.cateringName = document.getElementById('regCateringName')?.value.trim();
      payload.businessAddress = document.getElementById('regBusinessAddress')?.value.trim();
      payload.businessPhone = document.getElementById('regBusinessPhone')?.value.trim();
    }

    try {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';

      let res;
      try {
        res = await fetch('/api/auth/register/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
      } catch (networkErr) {
        throw new Error('Cannot reach the server. Check your internet connection and try again.');
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || `Registration failed (error ${res.status})`);

      this._token = data.data.registrationToken;
      document.getElementById('phoneDisplay').textContent = data.data.maskedPhone;

      // Auto-send phone OTP
      this.goToStep(3);
      await this._sendPhoneOtp();
    } catch (err) {
      showToast(err.message || 'Registration failed', 'danger');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-arrow-right me-2"></i>Continue to Verification';
    }
    return false;
  },

  // ─── Step 3: Phone OTP ─────────────────────────────────────────────────

  async _sendPhoneOtp() {
    try {
      let res;
      try {
        res = await fetch('/api/auth/register/phone/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ registrationToken: this._token })
        });
      } catch (networkErr) {
        throw new Error('Cannot reach the server. Check your internet connection and try again.');
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || `Failed to send code (error ${res.status})`);

      document.getElementById('phoneDisplay').textContent = data.data?.maskedPhone || '';
      this._startPhoneCooldown(data.data?.expiresIn || 300);
      showToast('Verification code sent to your phone', 'success');
    } catch (err) {
      showToast(err.message || 'Failed to send verification code. Please try again.', 'danger');
    }
  },

  _startPhoneCooldown(seconds = 60) {
    this._phoneCooldown = seconds;
    const timerEl = document.getElementById('phoneResendTimer');
    const resendBtn = document.getElementById('phoneResendBtn');
    timerEl.style.display = 'block';
    resendBtn.style.display = 'none';

    clearInterval(this._phoneTimer);
    this._phoneTimer = setInterval(() => {
      this._phoneCooldown--;
      if (this._phoneCooldown <= 0) {
        clearInterval(this._phoneTimer);
        timerEl.style.display = 'none';
        resendBtn.style.display = 'block';
      } else {
        timerEl.innerHTML = `Resend code in <strong>${this._phoneCooldown}s</strong>`;
      }
    }, 1000);
  },

  async resendPhone() {
    document.getElementById('phoneResendBtn').style.display = 'none';
    clearOtpInputs('phoneOtpGroup');
    try {
      const res = await fetch('/api/auth/register/resend-phone', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ registrationToken: this._token })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to resend');
      this._startPhoneCooldown(data.data?.expiresIn || 300);
      showToast('New verification code sent', 'success');
    } catch (err) {
      showToast(err.message || 'Failed to resend code', 'danger');
    }
  },

  async verifyPhone() {
    const otp = getOtpValue('phoneOtpGroup');
    if (otp.length !== 6) { showToast('Enter the complete 6-digit code', 'warning'); return; }

    const btn = document.getElementById('phoneVerifyBtn');
    try {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Verifying...';

      const res = await fetch('/api/auth/register/phone/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ registrationToken: this._token, otp })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Verification failed');

      clearInterval(this._phoneTimer);
      showToast('Phone number verified!', 'success');

      // Move to email verification
      setTimeout(() => {
        document.getElementById('emailDisplay').textContent = data.data?.maskedEmail || '';
        this.goToStep(4);
        this._sendEmailOtp();
      }, 800);
    } catch (err) {
      showToast(err.message || 'Verification failed', 'danger');
      clearOtpInputs('phoneOtpGroup');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-shield-check me-2"></i>Verify Phone';
    }
  },

  // ─── Step 4: Email OTP ─────────────────────────────────────────────────

  async _sendEmailOtp() {
    try {
      const res = await fetch('/api/auth/register/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ registrationToken: this._token })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to send email');

      document.getElementById('emailDisplay').textContent = data.data?.maskedEmail || '';
      this._startEmailCooldown(data.data?.expiresIn || 300);
      showToast('Verification code sent to your email', 'success');
    } catch (err) {
      showToast(err.message || 'Failed to send verification email', 'danger');
    }
  },

  _startEmailCooldown(seconds = 60) {
    this._emailCooldown = seconds;
    const timerEl = document.getElementById('emailResendTimer');
    const resendBtn = document.getElementById('emailResendBtn');
    timerEl.style.display = 'block';
    resendBtn.style.display = 'none';

    clearInterval(this._emailTimer);
    this._emailTimer = setInterval(() => {
      this._emailCooldown--;
      if (this._emailCooldown <= 0) {
        clearInterval(this._emailTimer);
        timerEl.style.display = 'none';
        resendBtn.style.display = 'block';
      } else {
        timerEl.innerHTML = `Resend code in <strong>${this._emailCooldown}s</strong>`;
      }
    }, 1000);
  },

  async resendEmail() {
    document.getElementById('emailResendBtn').style.display = 'none';
    clearOtpInputs('emailOtpGroup');
    try {
      const res = await fetch('/api/auth/register/resend-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ registrationToken: this._token })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to resend');
      this._startEmailCooldown(data.data?.expiresIn || 300);
      showToast('New verification code sent to your email', 'success');
    } catch (err) {
      showToast(err.message || 'Failed to resend code', 'danger');
    }
  },

  async verifyEmail() {
    const otp = getOtpValue('emailOtpGroup');
    if (otp.length !== 6) { showToast('Enter the complete 6-digit code', 'warning'); return; }

    const btn = document.getElementById('emailVerifyBtn');
    try {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Verifying...';

      const res = await fetch('/api/auth/register/email/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ registrationToken: this._token, otp })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Verification failed');

      clearInterval(this._emailTimer);
      showToast('Email verified!', 'success');

      setTimeout(() => {
        document.getElementById('regSuccessPending').style.display = 'block';
        document.getElementById('regSuccessDone').style.display = 'none';
        this.goToStep(5);
      }, 800);
    } catch (err) {
      showToast(err.message || 'Verification failed', 'danger');
      clearOtpInputs('emailOtpGroup');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-shield-check me-2"></i>Verify Email';
    }
  },

  // ─── Step 5: Complete Registration ─────────────────────────────────────

  async completeRegistration() {
    const btn = document.getElementById('regCompleteBtn');
    try {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Creating account...';

      const res = await fetch('/api/auth/register/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ registrationToken: this._token })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Registration failed');

      // Store auth data for automatic login
      const authData = data.data;
      localStorage.setItem('ptj_token', authData.token);
      localStorage.setItem('ptj_user', JSON.stringify(authData));

      document.getElementById('regSuccessPending').style.display = 'none';
      document.getElementById('regSuccessDone').style.display = 'block';
      showToast('Account created successfully! Welcome to PartTime Job.', 'success');

    } catch (err) {
      showToast(err.message || 'Registration failed', 'danger');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-check-circle me-2"></i>Complete Registration';
    }
  },

  goToLogin() {
    // If auth data was saved, redirect to appropriate dashboard
    const user = (() => { try { return JSON.parse(localStorage.getItem('ptj_user')); } catch { return null; } })();
    if (user && user.token) {
      if (user.role === 'ROLE_STUDENT') window.location.href = '/#student-dashboard';
      else if (user.role === 'ROLE_OWNER') window.location.href = '/#owner-dashboard';
      else window.location.href = '/';
    } else {
      window.location.href = '/';
    }
  }
};
