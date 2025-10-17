// Centralized configuration for observability stack
module.exports = {
  // Service Configuration
  SERVICE_NAME: process.env.SERVICE_NAME || 'demo-mern-app',
  SERVICE_VERSION: process.env.SERVICE_VERSION || '1.0.0',
  NODE_ENV: process.env.NODE_ENV || 'development',
  
  // Observability Stack URLs
  OPENSEARCH_URL: process.env.OPENSEARCH_URL || 'http://opensearch:9200',
  LOKI_URL: process.env.LOKI_URL || 'http://loki:3100',
  PROMETHEUS_URL: process.env.PROMETHEUS_URL || 'http://prometheus:9090',
  JAEGER_URL: process.env.JAEGER_URL || 'http://jaeger:16686',
  PUSHGATEWAY_URL: process.env.PUSHGATEWAY_URL || 'http://pushgateway:9091',
  
  // MongoDB Configuration
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/devopsark-dev',
  DATABASE_NAME: process.env.DATABASE_NAME || 'devopsark-dev',
  COLLECTION_NAME: process.env.COLLECTION_NAME || 'observabilityIntegrations',
  
  // Jaeger Configuration
  JAEGER_AGENT_HOST: process.env.JAEGER_AGENT_HOST || 'jaeger',
  JAEGER_AGENT_PORT: process.env.JAEGER_AGENT_PORT || 6832,
  
  // Data Pipeline Configuration
  PIPELINE_INTERVAL: parseInt(process.env.PIPELINE_INTERVAL) || 30000, // 30 seconds
  MAX_FAILURES: parseInt(process.env.MAX_FAILURES) || 5,
  RETRY_DELAY: parseInt(process.env.RETRY_DELAY) || 5000,
  
  // Loki Configuration
  LOKI_BATCH_SIZE: parseInt(process.env.LOKI_BATCH_SIZE) || 10,
  LOKI_BATCH_TIMEOUT: parseInt(process.env.LOKI_BATCH_TIMEOUT) || 5000,
  LOKI_RETRY_ATTEMPTS: parseInt(process.env.LOKI_RETRY_ATTEMPTS) || 3,
  LOKI_RETRY_DELAY: parseInt(process.env.LOKI_RETRY_DELAY) || 1000,
  LOKI_CIRCUIT_BREAKER_THRESHOLD: parseInt(process.env.LOKI_CIRCUIT_BREAKER_THRESHOLD) || 5,
  
  // Logging Configuration
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  ENABLE_LOCAL_LOGS: process.env.ENABLE_LOCAL_LOGS === 'true',
  
  // Repository Configuration
  REPOSITORY_URL: process.env.REPOSITORY_URL,
  ORGANISATION_ID: process.env.ORGANISATION_ID,
  PROJECT_ID: process.env.PROJECT_ID,
  OBSERVABILITY_API_KEY: process.env.OBSERVABILITY_API_KEY
};