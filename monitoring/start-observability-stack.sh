#!/bin/bash

# Observability Stack Startup Script
# This script starts the complete observability stack (Prometheus + Loki + Jaeger + Grafana)

set -e

echo "🚀 Starting Observability Stack (Prometheus + Loki + Jaeger + Grafana)..."

# Load environment variables (if any)
if [ -f ".env" ]; then
    echo "📋 Loading environment variables..."
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose down --remove-orphans

# Start the stack
echo "🚀 Starting observability stack..."
docker-compose up -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be healthy..."

# Wait for Prometheus
echo "📊 Waiting for Prometheus..."
timeout 60 bash -c 'until curl -f http://localhost:9090/-/healthy > /dev/null 2>&1; do sleep 2; done'
echo "✅ Prometheus is ready!"

# Wait for Loki
echo "📝 Waiting for Loki..."
timeout 60 bash -c 'until curl -f http://localhost:3100/ready > /dev/null 2>&1; do sleep 2; done'
echo "✅ Loki is ready!"

# Wait for Jaeger
echo "🔍 Waiting for Jaeger..."
timeout 60 bash -c 'until curl -f http://localhost:16686/ > /dev/null 2>&1; do sleep 2; done'
echo "✅ Jaeger is ready!"

# Wait for Grafana
echo "📈 Waiting for Grafana..."
timeout 60 bash -c 'until curl -f http://localhost:3001/api/health > /dev/null 2>&1; do sleep 2; done'
echo "✅ Grafana is ready!"

echo ""
echo "🎉 Observability Stack is running!"
echo ""
echo "📊 Services:"
echo "  - Prometheus: http://localhost:9090"
echo "  - Loki: http://localhost:3100"
echo "  - Jaeger UI: http://localhost:16686"
echo "  - Grafana: http://localhost:3001 (admin/admin)"
echo ""
echo "📝 To test the stack:"
echo "  1. Start your Node.js application with observability setup"
echo "  2. Make some requests to generate logs, metrics, and traces"
echo "  3. Check Grafana dashboard at http://localhost:3001"
echo "  4. Check Jaeger UI at http://localhost:16686"
echo ""
echo "🛑 To stop the stack:"
echo "  docker-compose down"