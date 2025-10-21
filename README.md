# Example Node.js App

This is a simple Node.js Express application.

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

