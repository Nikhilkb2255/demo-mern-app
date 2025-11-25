const winston = require('winston');
const promClient = require('prom-client');
const jaeger = require('jaeger-client');
const opentracing = require('opentracing');
const ObservabilityHttpClient = require('./http-transmission-client');
const config = require('./config');

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

// Initialize HTTP client
const httpClient = new ObservabilityHttpClient();

// Batch processing for HTTP transmission
class HttpBatchProcessor {
  constructor() {
    this.logs = [];
    this.metrics = [];
    this.traces = [];
    this.batchSize = config.HTTP_BATCH_SIZE;
    this.batchTimeout = config.HTTP_BATCH_TIMEOUT;
    this.timeout = null;
  }

  addLog(log) {
    this.logs.push(log);
    this.checkBatchSize();
  }

  addMetric(metric) {
    this.metrics.push(metric);
    this.checkBatchSize();
  }

  addTrace(trace) {
    this.traces.push(trace);
    this.checkBatchSize();
  }

  checkBatchSize() {
    if (this.logs.length + this.metrics.length + this.traces.length >= this.batchSize) {
      this.flush();
    } else if (!this.timeout) {
      this.timeout = setTimeout(() => this.flush(), this.batchTimeout);
    }
  }

  async flush() {
    if (this.logs.length === 0 && this.metrics.length === 0 && this.traces.length === 0) {
      return;
    }

    const batch = {
      logs: [...this.logs],
      metrics: [...this.metrics],
      traces: [...this.traces]
    };

    // Clear arrays
    this.logs = [];
    this.metrics = [];
    this.traces = [];

    // Clear timeout
    if (this.timeout) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }

    // Send batch
    try {
      await httpClient.sendBatch(batch);
    } catch (error) {
      console.error('❌ Failed to send batch:', error.message);
    }
  }
}

const batchProcessor = new HttpBatchProcessor();

// Custom Winston transport for HTTP transmission
class HttpTransport extends winston.Transport {
  constructor(options) {
    super(options);
    this.name = 'http';
    this.level = options.level || 'info';
  }

  log(info, callback) {
    if (this.silent) {
      return callback();
    }

    const logEntry = {
      timestamp: info.timestamp,
      level: info.level,
      message: info.message,
      service: config.SERVICE_NAME,
      version: config.SERVICE_VERSION,
      environment: config.NODE_ENV,
      ...info
    };

    batchProcessor.addLog(logEntry);
    callback();
  }
}

// Initialize Jaeger tracer
const initJaeger = () => {
  const jaegerConfig = {
    serviceName: config.SERVICE_NAME,
    sampler: {
      type: 'const',
      param: 1,
    },
    reporter: {
      logSpans: true,
      agentHost: config.JAEGER_AGENT_HOST,
      agentPort: config.JAEGER_AGENT_PORT,
    },
  };

  const options = {
    tags: {
      'service.version': config.SERVICE_VERSION,
      'service.environment': config.NODE_ENV,
    },
  };

  return jaeger.initTracer(jaegerConfig, options);
};

// Initialize Winston logger with HTTP transport
const initLogger = () => {
  const logger = winston.createLogger({
    level: config.LOG_LEVEL,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: {
      service: config.SERVICE_NAME,
      version: config.SERVICE_VERSION,
      environment: config.NODE_ENV,
    },
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        ),
      }),
    ],
  });

  // Add HTTP transport if enabled
  if (config.HTTP_TRANSMISSION_ENABLED) {
    logger.add(new HttpTransport({
      level: 'info'
    }));
  }

  return logger;
};

// Setup observability middleware
const setupObservability = (app) => {
  const logger = initLogger();
  const tracer = initJaeger();

  // Health check endpoint
  app.get('/health', (req, res) => {
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: config.SERVICE_NAME,
      version: config.SERVICE_VERSION,
      uptime: process.uptime(),
      memory: process.memoryUsage()
    };

    // Send health status via HTTP if enabled
    if (config.HTTP_TRANSMISSION_ENABLED) {
      httpClient.sendHealthStatus(healthStatus).catch(err => {
        console.error('Failed to send health status:', err.message);
      });
    }

    res.json(healthStatus);
  });

  // Request logging and metrics middleware
  app.use((req, res, next) => {
    const start = Date.now();
    const span = tracer.startSpan(`${req.method} ${req.route?.path || req.path}`);

    req.span = span;
    req.traceId = span.context().toTraceId();
    req.spanCount = 1; // Initialize span counter
    
    // Automatically create child spans for common operations
    req.autoSpans = {
      dbSpan: null,
      processSpan: null,
      validationSpan: null,
      graphqlSpan: null,
      resolverSpan: null,
      appSpan: null,
      rootSpan: null
    };

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
    
    // Automatically create child spans based on route
    if (req.url.startsWith('/api/')) {
      // Create database span for API routes
      req.autoSpans.dbSpan = createChildSpan(req, 'database.query', {
        'db.operation': req.method === 'GET' ? 'SELECT' : req.method === 'POST' ? 'INSERT' : req.method === 'PUT' ? 'UPDATE' : 'DELETE',
        'db.table': req.url.replace('/api/', '').replace('/', '_'),
        'db.system': 'postgresql'
      });
      
      // Create processing span
      req.autoSpans.processSpan = createChildSpan(req, 'data.processing', {
        'operation': 'process_request',
        'route': req.url
      });
      
      // Create validation span for POST/PUT requests
      if (req.method === 'POST' || req.method === 'PUT') {
        req.autoSpans.validationSpan = createChildSpan(req, 'data.validation', {
          'operation': 'validate_input',
          'route': req.url
        });
      }
    } else if (req.url.startsWith('/graphql')) {
      // Create GraphQL-specific spans
      req.autoSpans.graphqlSpan = createChildSpan(req, 'graphql.operation', {
        'graphql.endpoint': '/graphql',
        'graphql.method': req.method
      });
      
      // Create resolver span
      req.autoSpans.resolverSpan = createChildSpan(req, 'graphql.resolver', {
        'graphql.resolver': 'execute_resolvers'
      });
      
      // Create data processing span
      req.autoSpans.processSpan = createChildSpan(req, 'graphql.processing', {
        'operation': 'process_graphql_response'
      });
    } else {
      // Create spans for all other routes (including root route)
      // Create application logic span
      req.autoSpans.appSpan = createChildSpan(req, 'application.logic', {
        'app.operation': 'handle_request',
        'app.route': req.url,
        'app.method': req.method
      });
      
      // Create processing span
      req.autoSpans.processSpan = createChildSpan(req, 'data.processing', {
        'operation': 'process_response',
        'route': req.url
      });
      
      // Create additional span for root route
      if (req.url === '/') {
        req.autoSpans.rootSpan = createChildSpan(req, 'application.root', {
          'app.endpoint': 'root',
          'app.purpose': 'welcome_page'
        });
      }
    }

    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
      const duration = (Date.now() - start) / 1000;

      // Update Prometheus metrics
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

      // Send metrics via HTTP if enabled
      if (config.HTTP_TRANSMISSION_ENABLED) {
        const metricData = {
          name: 'http_request_duration_seconds',
          value: duration,
          labels: {
            method: req.method,
            route: req.route?.path || req.path,
            status_code: res.statusCode.toString()
          },
          timestamp: new Date().toISOString()
        };
        batchProcessor.addMetric(metricData);
      }

      logger.info('Request completed', {
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration: duration,
        traceId: req.traceId,
        ...userContext,
      });

      // Send trace summary via HTTP if enabled
      if (config.HTTP_TRANSMISSION_ENABLED) {
        // Count actual spans from the completed trace
        const spanCount = req.spanCount || 1;
        const traceSummary = {
          traceId: req.traceId,
          duration: duration * 1000000, // Convert to microseconds
          spans: spanCount,
          timestamp: new Date().toISOString(),
          url: req.url,
          path: req.route?.path || req.path,
          method: req.method,
          service: config.SERVICE_NAME,
          applicationType: 'nodejs',
          is_trace_summary: true
        };
        batchProcessor.addTrace(traceSummary);
      }

      // Automatically finish child spans
      if (req.autoSpans) {
        if (req.autoSpans.validationSpan) {
          finishChildSpan(req.autoSpans.validationSpan, {
            'validation.status': 'completed',
            'validation.records': 1
          });
        }
        if (req.autoSpans.processSpan) {
          finishChildSpan(req.autoSpans.processSpan, {
            'processing.status': 'completed',
            'processing.records': 1
          });
        }
        if (req.autoSpans.dbSpan) {
          finishChildSpan(req.autoSpans.dbSpan, {
            'db.rows_returned': 1,
            'db.query_time': '15ms'
          });
        }
        if (req.autoSpans.graphqlSpan) {
          finishChildSpan(req.autoSpans.graphqlSpan, {
            'graphql.operation_completed': true,
            'graphql.response_time': duration + 's'
          });
        }
        if (req.autoSpans.resolverSpan) {
          finishChildSpan(req.autoSpans.resolverSpan, {
            'graphql.resolvers_executed': 1,
            'graphql.resolver_time': '10ms'
          });
        }
        if (req.autoSpans.appSpan) {
          finishChildSpan(req.autoSpans.appSpan, {
            'app.status': 'completed',
            'app.response_time': duration + 's'
          });
        }
        if (req.autoSpans.rootSpan) {
          finishChildSpan(req.autoSpans.rootSpan, {
            'app.welcome_page': 'served',
            'app.timestamp': new Date().toISOString()
          });
        }
      }

      span.setTag('http.status_code', res.statusCode);
      span.setTag('http.method', req.method);
      span.setTag('http.url', req.url);
      
      // Serialize and send root span if HTTP transmission is enabled
      if (config.HTTP_TRANSMISSION_ENABLED) {
        const rootSpanData = serializeSpan(span);
        if (rootSpanData) {
          batchProcessor.addTrace(rootSpanData);
        }
      }
      
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
      
      // Serialize and send error span if HTTP transmission is enabled
      if (config.HTTP_TRANSMISSION_ENABLED) {
        const errorSpanData = serializeSpan(req.span);
        if (errorSpanData) {
          batchProcessor.addTrace(errorSpanData);
        }
      }
      
      req.span.finish();
    }

    res.status(500).json({
      error: 'Internal Server Error',
      message: err.message,
      traceId: req.traceId,
    });
  });

  // Periodic health status transmission
  if (config.HTTP_TRANSMISSION_ENABLED) {
    setInterval(async () => {
      const healthStatus = {
        status: 'healthy',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        timestamp: new Date().toISOString()
      };
      
      try {
        await httpClient.sendHealthStatus(healthStatus);
      } catch (error) {
        console.error('Failed to send periodic health status:', error.message);
      }
    }, 60000); // Every minute
  }

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('🛑 Shutting down HTTP observability...');
    await batchProcessor.flush();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('🛑 Shutting down HTTP observability...');
    await batchProcessor.flush();
    process.exit(0);
  });

  // Helper function to create child spans
  const createChildSpan = (req, operationName, tags = {}) => {
    if (!req.span) return null;
    
    const childSpan = tracer.startSpan(operationName, { childOf: req.span });
    req.spanCount = (req.spanCount || 1) + 1;
    
    // Add tags to the child span
    Object.keys(tags).forEach(key => {
      childSpan.setTag(key, tags[key]);
    });
    
    return childSpan;
  };

  // Helper function to serialize Jaeger span data
  const serializeSpan = (span) => {
    if (!span) return null;
    
    try {
      // Get span context
      const context = span.context();
      const traceId = context.toTraceId();
      const spanId = context.toSpanId();
      const parentSpanId = span._parentSpanId ? span._parentSpanId.context().toSpanId() : null;
      
      // Calculate duration in microseconds
      const duration = span._duration ? span._duration * 1000 : 0; // Convert to microseconds
      
      // Extract tags from span
      const tags = {};
      if (span._tags) {
        Object.keys(span._tags).forEach(key => {
          const tag = span._tags[key];
          if (typeof tag === 'string' || typeof tag === 'number' || typeof tag === 'boolean') {
            tags[key] = tag;
          } else if (tag && typeof tag === 'object') {
            tags[key] = JSON.stringify(tag);
          }
        });
      }
      
      // Get start time
      const startTime = span._startTime ? new Date(span._startTime / 1000).toISOString() : new Date().toISOString();
      
      return {
        traceId: traceId,
        spanId: spanId,
        parentSpanId: parentSpanId,
        operationName: span._operationName || 'unknown',
        startTime: startTime,
        duration: Math.round(duration),
        service: config.SERVICE_NAME,
        tags: tags,
        timestamp: new Date().toISOString(),
        applicationType: 'nodejs',
        is_span: true
      };
    } catch (error) {
      console.error('❌ Failed to serialize span:', error.message);
      return null;
    }
  };

  // Helper function to finish child spans and send them
  const finishChildSpan = (childSpan, tags = {}) => {
    if (!childSpan) return;
    
    // Add final tags
    Object.keys(tags).forEach(key => {
      childSpan.setTag(key, tags[key]);
    });
    
    // Serialize and send individual span if HTTP transmission is enabled
    if (config.HTTP_TRANSMISSION_ENABLED) {
      const spanData = serializeSpan(childSpan);
      if (spanData) {
        batchProcessor.addTrace(spanData);
      }
    }
    
    childSpan.finish();
  };

  return { 
    logger, 
    tracer, 
    metrics: { httpRequestsTotal, httpRequestDuration, activeConnections },
    httpClient,
    batchProcessor,
    createChildSpan,
    finishChildSpan,
    serializeSpan
  };
};

module.exports = {
  setupObservability,
  initLogger,
  initJaeger,
  register,
  httpRequestsTotal,
  httpRequestDuration,
  activeConnections,
  ObservabilityHttpClient
};