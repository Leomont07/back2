const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const winston = require('winston');
const fs = require('fs');
require('dotenv').config({ path: '../.env' });

const PORT = process.env.PORT || 5002;
const serviceAccount = {
    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL
  };

// Initialize Firebase
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
} else {
    admin.app();
}

const db = admin.firestore();
const routes = require("./routes/routes");

// Winston logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/local_logs.log' }),
    ],
});

const server = express();
server.use(cors({ origin: "http://localhost:3000", credentials: true }));
server.use(bodyParser.json());

// Logging middleware
server.use((req, res, next) => {
    console.log(`[${req.method}] ${req.url} - Body:`, req.body);
    const startTime = Date.now();
    res.on('finish', async () => {
        const logLevel = res.statusCode >= 400 ? 'error' : 'info';
        const responseTime = Date.now() - startTime;
        const logData = {
            server: 'Servidor2',
            level: logLevel,
            timestamp: new Date(),
            method: req.method,
            url: req.url,
            status: res.statusCode,
            responseTime,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
        };

        logger.log({ level: logLevel, message: 'Request completed', ...logData });
        fs.appendFileSync('logs/local_logs.log', JSON.stringify(logData) + '\n');
        try {
            await db.collection('logs').add(logData);
        } catch (error) {
            logger.error('Error al guardar log en Firestore:', error);
        }
    });
    next();
});

server.use("/api", routes);
server.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));