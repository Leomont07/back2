const express = require('express');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy'); 
const QRCode = require('qrcode');
const router = express.Router();
const db = admin.firestore();

const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
};

// GET /getInfo
router.get('/getInfo', (req, res) => {
    res.status(200).json({
        nodeVersion: process.version,
        student: {
            name: "José Leonardo Montero Núñez",
            group: "IDGS11",
        },
    });
});

// POST /register
router.post('/register', async (req, res) => {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
        return res.status(400).json({ message: 'Missing fields' });
    }
    if (!validateEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const secret = speakeasy.generateSecret({
            name: `Seguridad:${email}`,
            issuer: 'Seguridad',
        });

        const userRef = await db.collection('users').add({
            username,
            email,
            password: hashedPassword,
            totpSecret: secret.base32,
        });

        const otpauthUrl = secret.otpauth_url;
        const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);

        res.status(200).json({
            message: 'User registered successfully',
            userId: userRef.id,
            qrCode: qrCodeDataUrl,
        });
    } catch (error) {
        res.status(500).json({ message: 'Error en el registro', error: error.message });
    }
});

// POST /login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        return res.status(400).json({ message: 'Hay datos faltantes' });
    }
    if (!validateEmail(email)) {
        return res.status(400).json({ message: 'Formato de email inválido' });
    }

    try {
        const user = await db.collection('users').where('email', '==', email).get();
        if (user.empty) {
            return res.status(401).json({ message: 'No existe registro de este email' });
        }

        let userData;
        let userId;
        user.forEach(doc => {
            userData = doc.data();
            userId = doc.id;
        });

        const isMatch = await bcrypt.compare(password, userData.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }

        // Instead of sending an MFA code via email, we'll prompt for the OTP
        res.status(200).json({ message: 'Ingrese el codigo OTP de Google Authenticator', userId });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// POST /verify-mfa (Verify the OTP from Google Authenticator)
router.post('/verify-mfa', async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.status(400).json({ message: 'Missing userId or OTP' });
    }

    try {
        const userDoc = await db.collection('users').doc(userId).get();
        if (!userDoc.exists) {
            return res.status(400).json({ message: 'User not found' });
        }

        const userData = userDoc.data();
        const totpSecret = userData.totpSecret;

        const verified = speakeasy.totp.verify({
            secret: totpSecret,
            encoding: 'base32',
            token: otp,
            window: 1,
        });

        if (!verified) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        const token = jwt.sign({ id: userId, email: userData.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        console.log('JWT generado');

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// GET /logs
router.get('/logs', async (req, res) => {
    try {
        const logsSnapshot = await db.collection('logs').where('server', '==', 'servidor2').get();
        const logs = [];
        logsSnapshot.forEach(doc => {
            logs.push({ id: doc.id, ...doc.data() });
        });
        res.status(200).json(logs);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching logs', error: error.message });
    }
});

module.exports = router;