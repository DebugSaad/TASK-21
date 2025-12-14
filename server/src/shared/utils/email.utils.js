const nodemailer = require('nodemailer');

exports.sendOtpEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Login OTP',
        text: `Your OTP is ${otp}. This OTP is valid for 10 minutes.`
    });
};