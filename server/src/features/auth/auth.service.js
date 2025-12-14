const jwt = require("jsonwebtoken");
const {
  hashPassword,
  comparePassword,
} = require("../../shared/utils/hash.utils");
const { sendOtpEmail } = require("../../shared/utils/email.utils");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

class AuthService {
  constructor(authRepo) {
    this.authRepo = authRepo;
  }

  async register(body) {
    if (!body) throw new Error("Invalid Request Body");

    const { email, password, mfa } = body;

    if (!email) throw new Error("Email is required");
    if (!password) throw new Error("Password is required");

    const username = body.username ? body.username : email.split("@")[0];

    let mfaMode = "NONE";
    if (mfa && mfa.enabled === true) {
      mfaMode = mfa.mode || "FIRST_LOGIN_ONLY";
    }

    const existingUser = await this.authRepo.findByEmail(email);
    if (existingUser) {
      throw new Error("Email already exists");
    }

    const hashedPassword = await hashPassword(password);

    const newUser = await this.authRepo.createUser({
      username,
      email,
      hashedPassword,
      mfaMode,
      isVerified: false,
    });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await this.authRepo.saveOtp(email, otp);
    await sendOtpEmail(email, `Your Account Verification OTP is: ${otp}`);

    return {
      message:
        "User registered. OTP sent to email. Please verify to activate account.",
      mfaMode: mfaMode,
      action: "VERIFY_OTP_REQUIRED",
      email,
    };
  }

async verifyOtp(body, userAgent, ipAddress) {
    if (!body) throw new Error("Invalid Request Body");
    const { email, otp } = body;
    if (!email || !otp) throw new Error("Email and OTP are required");

    const validOtpRecord = await this.authRepo.getValidOtp(email, otp);

    if (!validOtpRecord) {
      throw new Error("Invalid or Expired OTP");
    }

    const user = await this.authRepo.findByEmail(email);
    if (!user) throw new Error("User not found");

    if (!user.is_verified) {
      await this.authRepo.verifyUser(email);
    }

    await this.authRepo.deleteOtp(validOtpRecord.id);
    const tokens = await this.generateAndSaveSession(
      user,
      userAgent,
      ipAddress
    );

    return {
      message: "Email verified successfully.",
      user: { id: user.id, email: user.email, username: user.username },
      tokens,
    };
}


async verifyLoginOtp(body, userAgent, ipAddress) {
    console.log("VerifyLoginOtp Called");
    console.log("Received Body:", JSON.stringify(body));

    if (!body) throw new Error("Invalid Request Body");
    let { email, otp } = body;

    if (!email || !otp) throw new Error("Email and OTP are required");

    const cleanEmail = email.toString().trim().toLowerCase();
    const cleanOtp = otp.toString().trim();

    console.log(`Checking DB for Email: '${cleanEmail}' and OTP: '${cleanOtp}'`);

    const validOtpRecord = await this.authRepo.getValidOtp(cleanEmail, cleanOtp);

    console.log("DB Result:", validOtpRecord);

    if (!validOtpRecord) {
      console.log("ERROR: Record not found or expired in DB");
      throw new Error("Invalid or Expired OTP");
    }

    console.log("SUCCESS: OTP Found, Logging in user...");

    const user = await this.authRepo.findByEmail(cleanEmail);
    if (!user) throw new Error("User not found");

    await this.authRepo.updateLastLogin(user.id);
    await this.authRepo.deleteOtp(validOtpRecord.id);

    const tokens = await this.generateAndSaveSession(
      user,
      userAgent,
      ipAddress
    );

    return {
      message: "Login verified successfully.",
      user: { id: user.id, email: user.email, username: user.username },
      tokens,
    };
}

async login(body, userAgent, ipAddress) {
    if (!body) throw new Error("Invalid Request Body");
    const { email, password } = body;
    if (!email || !password) throw new Error("Email and Password are required");

    const user = await this.authRepo.findByEmail(email);
    if (!user) {
      throw new Error("Invalid credentials");
    }

    const isMatch = await comparePassword(
      password,
      user.password_hash || user.password
    );
    if (!isMatch) {
      throw new Error("Invalid credentials");
    }

    if (!user.is_verified) {
      throw new Error("Account not verified. Please verify your email first.");
    }

    let shouldSendOtp = false;

    if (user.mfa_mode === "ALWAYS") {
      shouldSendOtp = true;
    }
    else if (user.mfa_mode === "FIRST_LOGIN_ONLY" && !user.last_login_at) {
      shouldSendOtp = true;
    }

    if (shouldSendOtp) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      
      await this.authRepo.saveOtp(email, otp, 'LOGIN'); 

      await sendOtpEmail(email, `Your Login OTP is: ${otp}`);
      console.log(`[LOGIN OTP] for ${email}: ${otp}`);

      return {
        message: "OTP sent to email. Please verify to complete login.",
        mfaRequired: true, 
        userId: user.id,   
        email: user.email
      };
    }

    await this.authRepo.updateLastLogin(user.id);

    const tokens = await this.generateAndSaveSession(
      user,
      userAgent,
      ipAddress
    );

    return {
      message: "Login successful",
      user: { id: user.id, email: user.email, username: user.username },
      tokens,
      mfaRequired: false,
    };
}

  async generateAndSaveSession(user, userAgent, ip) {
    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign({ id: user.id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    await this.authRepo.createSession(user.id, refreshToken, userAgent, ip);
    return { accessToken, refreshToken };
  }

  async forgotPassword(email) {
    if (!email) throw new Error("Email is required");

    const user = await this.authRepo.findByEmail(email);
    if (!user) throw new Error("User not found");

    const otp = crypto.randomInt(100000, 999999).toString();

    await this.authRepo.saveOtp(user.email, otp);

    const message = `Your Password Reset OTP is: ${otp}. It is valid for 10 minutes.`;
    await sendOtpEmail(user.email, message);

    return { message: "OTP sent to your email" };
  }

  async resetPassword(email, otp, newPassword) {
    const validOtpRecord = await this.authRepo.getValidOtp(email, otp);

    if (!validOtpRecord) {
      throw new Error("Invalid or Expired OTP");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await this.authRepo.updatePassword(email, hashedPassword);

    await this.authRepo.deleteOtp(validOtpRecord.id);

    return { message: "Password has been reset successfully" };
  }

  async handleGoogleLogin(profile, userAgent, ipAddress) {
    const email = profile.email;
    const googleId = profile.id;
    let user = await this.authRepo.findByGoogleId(googleId);

    if (!user) {
      user = await this.authRepo.findByEmail(email);

      if (user) {
        if (!user.google_id) {
          await this.authRepo.updateGoogleId(user.id, googleId);
          user.google_id = googleId;
        }
      } else {
        user = await this.authRepo.createGoogleUser(email, googleId);
      }
    }

    const tokens = await this.generateAndSaveSession(
      user,
      userAgent,
      ipAddress
    );
    return { user, tokens };
  }
}

module.exports = AuthService;
