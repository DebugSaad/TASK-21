const AuthRepository = require('./auth.repository');
const AuthService = require('./auth.service');
const AuthHandler = require('./auth.handler');
const pool = require('../../config/database');

async function authRoutes(fastify, options) {
    const authRepo = new AuthRepository(pool);
    const authService = new AuthService(authRepo);
    const authHandler = new AuthHandler(authService);

    fastify.post('/register', authHandler.registerHandler);
    fastify.post('/login', authHandler.loginHandler);

    fastify.post('/verify-otp', authHandler.verifyOtpHandler);
    fastify.post('/verify-login-otp', authHandler.verifyLoginOtpHandler);

    fastify.post('/forgot-password', authHandler.forgotPassword);
    fastify.post('/reset-password', authHandler.resetPassword);

    fastify.get('/google/callback', authHandler.googleCallback);
}

module.exports = authRoutes;

