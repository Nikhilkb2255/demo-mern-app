// Initialize HTTP Observability BEFORE any other imports
const { setupObservability } = require('./monitoring/http-observability-setup');

const express = require('express');
const cors = require('cors');

const app = express();
// Setup HTTP Observability (Winston + Prometheus + Jaeger + HTTP Transmission)
const { logger, tracer, httpClient, createChildSpan, finishChildSpan } = setupObservability(app);

const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.get('/', (req, res) => {
  logger.info('Route accessed', { path: '/', method: 'GET' });
  res.json({ 
    message: 'Hello from Example Node.js App!',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.get('/api/users', (req, res) => {
  logger.info('Route accessed', { path: '/api/users', method: 'GET' });
  const users = [
    { id: 1, name: 'John Doe', email: 'john@example.com' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com' },
    { id: 3, name: 'Bob Johnson', email: 'bob@example.com' }
  ];
  
  res.json({ users });
});

app.get('/api/health', (req, res) => {
  logger.info('Route accessed', { path: '/api/health', method: 'GET' });
  res.json({ 
    status: 'healthy',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString()
  });
});

app.get('/api/slow', (req, res) => {
  logger.info('Route accessed', { path: '/api/slow', method: 'GET' });
  // Simulate slow operation
  setTimeout(() => {
    res.json({ 
      message: 'This was a slow operation',
      duration: '2 seconds'
    });
  }, 2000);
});

app.get('/api/error', (req, res) => {
  logger.info('Route accessed', { path: '/api/error', method: 'GET' });
  res.status(500).json({ 
    error: 'This is a simulated error',
    code: 'SIMULATED_ERROR'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not Found',
    message: `Route ${req.method} ${req.path} not found`
  });
});

app.listen(PORT, () => {
  logger.info(`🚀 Example app running on port ${PORT}`);
  logger.info(`📊 Health check: http://localhost:${PORT}/api/health`);
});
