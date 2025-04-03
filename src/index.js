const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const winston = require('winston');
const fs = require('fs');
require('dotenv').config({ path: '../.env' });

const PORT = process.env.PORT || 5002;
const serviceAccount = require("./config/seguridad-83867-firebase-adminsdk-fbsvc-25c92b171e.json");

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