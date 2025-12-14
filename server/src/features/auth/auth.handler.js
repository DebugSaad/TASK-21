class AuthHandler {
  constructor(authService) {
    this.authService = authService;
    this.registerHandler = this.registerHandler.bind(this);
    this.verifyOtpHandler = this.verifyOtpHandler.bind(this);
    this.loginHandler = this.loginHandler.bind(this);
    this.verifyLoginOtpHandler = this.verifyLoginOtpHandler.bind(this); // Ye zaroori tha
    this.googleCallback = this.googleCallback.bind(this);
    this.loginGoogle = this.loginGoogle.bind(this);
    this.forgotPassword = this.forgotPassword.bind(this);
    this.resetPassword = this.resetPassword.bind(this);
  }

  async registerHandler(req, reply) {
    try {
      const result = await this.authService.register(req.body);
      return reply.code(201).send(result);
    } catch (err) {
      return reply.code(400).send({ message: err.message });
    }
  }

  async verifyOtpHandler(req, reply) {
    try {
      const userAgent = req.headers["user-agent"] || "Unknown";
      const ip = req.ip || req.socket.remoteAddress;

      const result = await this.authService.verifyOtp(req.body, userAgent, ip);
      return reply.code(200).send(result);
    } catch (error) {
      return reply.code(400).send({ message: error.message });
    }
  }

  async loginHandler(req, reply) {
    try {
      const userAgent = req.headers["user-agent"] || "Unknown";
      const ip = req.ip || req.socket.remoteAddress;

      const result = await this.authService.login(req.body, userAgent, ip);
      return reply.code(200).send(result);
    } catch (error) {
      const statusCode = error.message.includes("verified") ? 403 : 401;
      return reply.code(statusCode).send({ message: error.message });
    }
  }

  async verifyLoginOtpHandler(req, reply) {
    try {
      const userAgent = req.headers["user-agent"] || "Unknown";
      const ip = req.ip || req.socket.remoteAddress;

      const result = await this.authService.verifyLoginOtp(req.body, userAgent, ip);

      return reply.code(200).send(result);
    } catch (error) {
      return reply.code(400).send({ message: error.message });
    }
  }

  async loginGoogle(req, reply) {
    try {
      const authorizationEndpoint = await req.server.googleOAuth2.generateAuthorizationUri(req);
      
      return reply.redirect(authorizationEndpoint);
    } catch (err) {
      console.error("Google Redirect Error:", err);
      return reply.code(500).send({ message: "Google Redirect Failed" });
    }
  }

  async googleCallback(req, reply) {
    try {
      const token =
        await req.server.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(
          req
        );

      const userRes = await fetch(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        {
          headers: { Authorization: `Bearer ${token.token.access_token}` },
        }
      );
      const profile = await userRes.json();

      const userAgent = req.headers["user-agent"] || "Unknown";
      const ip = req.ip || req.socket.remoteAddress;

      const result = await this.authService.handleGoogleLogin(
        profile,
        userAgent,
        ip
      );

      return reply.send({ status: "success", ...result.tokens });
    } catch (err) {
      console.error(err);
      return reply.code(500).send({ message: "Google Login Failed" });
    }
  }

  async forgotPassword(req, reply) {
    try {
      const { email } = req.body;
      const result = await this.authService.forgotPassword(email);
      return reply.send(result);
    } catch (err) {
      return reply.code(400).send({ message: err.message });
    }
  }

  async resetPassword(req, reply) {
    try {
      const { email, otp, newPassword } = req.body;

      if (!email || !otp || !newPassword) {
        throw new Error("Email, OTP and New Password are required");
      }

      const result = await this.authService.resetPassword(
        email,
        otp,
        newPassword
      );
      return reply.send(result);
    } catch (err) {
      return reply.code(400).send({ message: err.message });
    }
  }
}

module.exports = AuthHandler;