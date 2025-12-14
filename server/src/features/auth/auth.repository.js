class AuthRepository {
  constructor(pool) {
    this.pool = pool;
  }

  // ---------------------------------------------------------
  // 1. CREATE USER
  // ---------------------------------------------------------
  async createUser(userData) {
    const { email, hashedPassword, mfaMode, isVerified, username } = userData;
    const query = `
            INSERT INTO users (email, password_hash, mfa_mode, is_verified, username) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id, email, mfa_mode, is_verified, username
        `;
    const result = await this.pool.query(query, [
      email,
      hashedPassword,
      mfaMode,
      isVerified,
      username,
    ]);
    return result.rows[0];
  }

  // ---------------------------------------------------------
  // 2. FIND USER BY EMAIL
  // ---------------------------------------------------------
  async findByEmail(email) {
    const query = `SELECT * FROM users WHERE email = $1`;
    const res = await this.pool.query(query, [email]);
    return res.rows[0] || null;
  }

  // ---------------------------------------------------------
  // 3. SAVE OTP (Unified for Login, Register & Reset)
  // ---------------------------------------------------------
  async saveOtp(email, otpCode, purpose) {
    // Note: 'purpose' hum receive kar rahey hain taake service file crash na ho,
    // lekin hum filhal saare OTPs 'otps' table me save kar rahey hain.

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 Minutes

    // 1. Pehle purana OTP delete karein to avoid duplicates
    await this.pool.query(`DELETE FROM otps WHERE email = $1`, [email]);

    // 2. Naya OTP Insert karein
    // Hum 'otp_code' column use kar rahey hain (jaisa aapke step 3 me tha)
    const query = `INSERT INTO otps (email, otp_code, expires_at) VALUES ($1, $2, $3)`;
    await this.pool.query(query, [email, otpCode, expiresAt]);
  }

  // ---------------------------------------------------------
  // 4. GET VALID OTP
  // ---------------------------------------------------------
  async getValidOtp(email, otp) {
    const query = `
      SELECT * FROM otps 
      WHERE email = $1 
      AND otp_code = $2 
      AND expires_at > NOW()
      LIMIT 1;
    `;

    try {
      const result = await this.pool.query(query, [email, otp]);
      return result.rows[0];
    } catch (error) {
      return null;
    }
  }

  // ---------------------------------------------------------
  // 5. DELETE OTP (Cleanup)
  // ---------------------------------------------------------
  async deleteOtp(id) {
    // ID se delete (agar aapke paas otp record ki id hai)
    await this.pool.query("DELETE FROM otps WHERE id = $1", [id]);
  }

  // ---------------------------------------------------------
  // 6. VERIFY USER (For Registration)
  // ---------------------------------------------------------
  async verifyUser(email) {
    const query = `UPDATE users SET is_verified = true WHERE email = $1`;
    await this.pool.query(query, [email]);
  }

  // ---------------------------------------------------------
  // 7. UPDATE LAST LOGIN (For MFA Logic)
  // ---------------------------------------------------------
  async updateLastLogin(userId) {
    const query = "UPDATE users SET last_login_at = NOW() WHERE id = $1";
    await this.pool.query(query, [userId]);
  }

  // ---------------------------------------------------------
  // 8. UPDATE PASSWORD
  // ---------------------------------------------------------
  async updatePassword(email, newPasswordHash) {
    const query = "UPDATE users SET password_hash = $1 WHERE email = $2";
    await this.pool.query(query, [newPasswordHash, email]);
  }

  // ---------------------------------------------------------
  // OTHER METHODS (Sessions, OAuth etc.)
  // ---------------------------------------------------------

  async createSession(userId, refreshToken, userAgent, ip) {
    const query = `
            INSERT INTO sessions (user_id, refresh_token, user_agent, ip_address, expires_at) 
            VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')
        `;
    await this.pool.query(query, [userId, refreshToken, userAgent, ip]);
  }

  async findById(id) {
    const result = await this.pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    return result.rows[0];
  }

  async findByGoogleId(googleId) {
    const result = await this.pool.query(
      "SELECT * FROM users WHERE google_id = $1",
      [googleId]
    );
    return result.rows[0];
  }

  async createGoogleUser(email, googleId) {
    const result = await this.pool.query(
      `INSERT INTO users (email, google_id, password_hash, is_verified) 
             VALUES ($1, $2, 'GOOGLE_AUTH', TRUE) RETURNING *`,
      [email, googleId]
    );
    return result.rows[0];
  }

  async updateGoogleId(userId, googleId) {
    const query = `UPDATE users SET google_id = $1 WHERE id = $2 RETURNING *`;
    const values = [googleId, userId];
    try {
      const result = await this.pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      console.error("Error updating Google ID:", error);
      throw new Error("Database Update Failed");
    }
  }
}

module.exports = AuthRepository;
