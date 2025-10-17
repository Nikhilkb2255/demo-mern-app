const winston = require('winston');
const promClient = require('prom-client');
const jaeger = require('jaeger-client');
const opentracing = require('opentracing');

// Initialize Prometheus metrics
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
  registers: [register]
});

const activeConnections = new promClient.Gauge({
  name: 'active_connections',
  help: 'Number of active connections',
  registers: [register]
});

// Initialize Jaeger tracer
const initJaeger = () => {
  const config = {
    serviceName: process.env.SERVICE_NAME || 'demo-mern-app',
    sampler: {
      type: 'const',
      param: 1,
    },
    reporter: {
      logSpans: true,
      agentHost: process.env.JAEGER_AGENT_HOST || 'localhost',
      agentPort: process.env.JAEGER_AGENT_PORT || 6832,
    },
  };

  const options = {
    tags: {
      'service.version': process.env.SERVICE_VERSION || '1.0.0',
      'service.environment': process.env.NODE_ENV || 'development',
    },
  };

  return jaeger.initTracer(config, options);
};

// Initialize Winston logger
const initLogger = () => {
  return winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: {
      service: process.env.SERVICE_NAME || 'demo-mern-app',
      version: process.env.SERVICE_VERSION || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
    },
    transports: [
      new winston.transports.File({
        filename: '/var/log/app/error.log',
        level: 'error',
      }),
      new winston.transports.File({
        filename: '/var/log/app/combined.log',
      }),
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        ),
      }),
    ],
  });
};

// Setup observability middleware
const setupObservability = (app) => {
  const logger = initLogger();
  const tracer = initJaeger();

  // Prometheus metrics endpoint
  app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  });

  // Request logging and metrics middleware
  app.use((req, res, next) => {
    const start = Date.now();
    const span = tracer.startSpan(`${req.method} ${req.route?.path || req.path}`);

    req.span = span;
    req.traceId = span.context().toTraceId();

    // Add user context to logs
    const userContext = {
      apiKey: req.observabilityApiKey ? req.observabilityApiKey.substring(0, 8) + '...' : null,
      repositoryUrl: req.repositoryUrl,
      projectName: req.projectName,
      organisationID: req.organisationID,
      projectID: req.projectID
    };

    logger.info('Incoming request', {
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      traceId: req.traceId,
      ...userContext,
    });

    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
      const duration = (Date.now() - start) / 1000;

      httpRequestsTotal.inc({
        method: req.method,
        route: req.route?.path || req.path,
        status_code: res.statusCode,
      });

      httpRequestDuration.observe({
        method: req.method,
        route: req.route?.path || req.path,
        status_code: res.statusCode,
      }, duration);

      logger.info('Request completed', {
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration: duration,
        traceId: req.traceId,
        ...userContext,
      });

      span.setTag('http.status_code', res.statusCode);
      span.setTag('http.method', req.method);
      span.setTag('http.url', req.url);
      span.finish();

      originalEnd.call(this, chunk, encoding);
    };

    next();
  });

  // Error handling middleware
  app.use((err, req, res, next) => {
    const userContext = {
      apiKey: req.observabilityApiKey ? req.observabilityApiKey.substring(0, 8) + '...' : null,
      repositoryUrl: req.repositoryUrl,
      projectName: req.projectName,
      organisationID: req.organisationID,
      projectID: req.projectID
    };

    logger.error('Request error', {
      error: err.message,
      stack: err.stack,
      method: req.method,
      url: req.url,
      traceId: req.traceId,
      ...userContext,
    });

    if (req.span) {
      req.span.setTag('error', true);
      req.span.log({
        event: 'error',
        message: err.message,
        stack: err.stack,
      });
      req.span.finish();
    }

    res.status(500).json({
      error: 'Internal Server Error',
      message: err.message,
      traceId: req.traceId,
    });
  });

  return { logger, tracer, metrics: { httpRequestsTotal, httpRequestDuration, activeConnections } };
};

module.exports = {
  setupObservability,
  initLogger,
  initJaeger,
  register,
  httpRequestsTotal,
  httpRequestDuration,
  activeConnections,
};