#!/bin/bash

echo "🚀 Starting Application with HTTP Observability"

# Load environment variables (if any)
if [ -f .env ]; then
    echo "📄 Loading environment variables from .env file..."
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check if required environment variables are set
if [ -z "$BACKEND_URL" ]; then
    echo "❌ BACKEND_URL is not set. Please set it in your .env file."
    exit 1
fi

if [ -z "$OBSERVABILITY_API_KEY" ]; then
    echo "❌ OBSERVABILITY_API_KEY is not set. Please set it in your .env file."
    exit 1
fi

if [ -z "$ORGANISATION_ID" ]; then
    echo "❌ ORGANISATION_ID is not set. Please set it in your .env file."
    exit 1
fi

if [ -z "$PROJECT_ID" ]; then
    echo "❌ PROJECT_ID is not set. Please set it in your .env file."
    exit 1
fi

echo "✅ Environment variables validated"

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Start the application
echo "🚀 Starting your application with HTTP observability..."
npm start

echo "✅ Application with HTTP observability is running!"
echo ""
echo "📊 Observability Stack:"
echo "  • Logs: App → Winston → HTTP → Backend → OpenSearch"
echo "  • Metrics: App → Prometheus Client → HTTP → Backend → OpenSearch"
echo "  • Traces: App → Jaeger Client → HTTP → Backend → OpenSearch"
echo ""
echo "🔧 Services:"
echo "  • Your App: http://localhost:3000"
echo "  • Backend: ${BACKEND_URL}"
echo "  • OpenSearch Dashboards: Check your backend for OpenSearch URL"
echo ""
echo "✅ All telemetry data is automatically sent to the backend via HTTP!";
