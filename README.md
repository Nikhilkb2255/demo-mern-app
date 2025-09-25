# Example Node.js App

This is a simple Node.js Express application that demonstrates how to integrate observability features using our automatic integration script.

## Features

- **Express.js** web server
- **CORS** enabled
- **JSON** API endpoints
- **Error handling** middleware
- **Health check** endpoint

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Welcome message |
| GET | `/api/users` | Get list of users |
| GET | `/api/health` | Health check with system info |
| GET | `/api/slow` | Simulate slow operation (2s delay) |
| GET | `/api/error` | Simulate error (500 status) |

## Before Integration

This app has no observability features - no metrics, logging, or tracing.

## After Integration

After running the integration script, this app will have:

- ✅ **Metrics** collection (Prometheus)
- ✅ **Structured logging** (Winston)
- ✅ **Distributed tracing** (Jaeger)
- ✅ **Health monitoring** endpoint
- ✅ **Request tracking** middleware

## How to Use

### 1. Install Dependencies
```bash
npm install
```

### 2. Run the App
```bash
npm start
```

### 3. Test Endpoints
```bash
# Welcome message
curl http://localhost:3000/

# Get users
curl http://localhost:3000/api/users

# Health check
curl http://localhost:3000/api/health

# Slow operation
curl http://localhost:3000/api/slow

# Error simulation
curl http://localhost:3000/api/error
```

## Integration with Observability

To add observability features to this app:

```bash
# Run the integration script
./scripts/auto-integrate-observability.sh -p ./example-app -b

# Start monitoring stack
docker-compose -f docker-compose.observability.yml up -d

# Start the app (now with observability)
npm start
```

After integration, you'll have:

- **Metrics**: http://localhost:3000/metrics
- **Health**: http://localhost:3000/health
- **Jaeger**: http://localhost:16686
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3001

## What Changes After Integration

The integration script will:

1. **Add OpenTelemetry initialization** at the top of `index.js`
2. **Add observability setup** after Express app creation
3. **Install observability package** in `node_modules/`
4. **Create configuration files** (`.env`, `docker-compose.observability.yml`, etc.)
5. **Add automatic middleware** for request tracking

The app will work exactly the same, but now with full observability!
