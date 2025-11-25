// Centralized configuration for HTTP observability transmission
module.exports = {
  // Service Configuration
  SERVICE_NAME: process.env.SERVICE_NAME || 'node-app',
  SERVICE_VERSION: process.env.SERVICE_VERSION || '1.0.0',
  NODE_ENV: process.env.NODE_ENV || 'development',
  
  // HTTP Transmission Configuration
  BACKEND_URL: process.env.BACKEND_URL || 'http://localhost:4000',
  HTTP_TRANSMISSION_ENABLED: process.env.HTTP_TRANSMISSION_ENABLED === 'true',
  HTTP_BATCH_SIZE: parseInt(process.env.HTTP_BATCH_SIZE) || 10,
  HTTP_BATCH_TIMEOUT: parseInt(process.env.HTTP_BATCH_TIMEOUT) || 5000,
  HTTP_RETRY_ATTEMPTS: parseInt(process.env.HTTP_RETRY_ATTEMPTS) || 3,
  HTTP_RETRY_DELAY: parseInt(process.env.HTTP_RETRY_DELAY) || 1000,
  
  // Jaeger Configuration (for local tracing)
  JAEGER_AGENT_HOST: process.env.JAEGER_AGENT_HOST || 'localhost',
  JAEGER_AGENT_PORT: process.env.JAEGER_AGENT_PORT || 6832,
  
  // Logging Configuration
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  ENABLE_LOCAL_LOGS: process.env.ENABLE_LOCAL_LOGS === 'true',
  
  // Repository Configuration
  REPOSITORY_URL: process.env.REPOSITORY_URL,
  ORGANISATION_ID: process.env.ORGANISATION_ID,
  PROJECT_ID: process.env.PROJECT_ID,
  OBSERVABILITY_API_KEY: process.env.OBSERVABILITY_API_KEY
};