// Winston Logger Configuration for DevOpsark Observability
const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure log directory exists
const logDir = process.env.LOG_DIR || '/var/log/app';
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Configure Winston logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { 
        service: process.env.SERVICE_NAME || 'demo-mern-app',
        version: process.env.SERVICE_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    },
    transports: [
        // Console transport
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        // File transport for Promtail to scrape
        new winston.transports.File({
            filename: path.join(logDir, 'application.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        // Error log file
        new winston.transports.File({
            filename: path.join(logDir, 'error.log'),
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        })
    ]
});

// Create a stream for Morgan HTTP logging
logger.stream = {
    write: (message) => {
        logger.info(message.trim());
    }
};

module.exports = logger;