#!/bin/bash

# OTLP Stack Startup Script
echo "🚀 Starting OTLP Observability Stack with MongoDB Validation..."

# Load environment variables
if [ -f "env.otlp" ]; then
    echo "📋 Loading environment variables..."
    export $(cat env.otlp | grep -v '^#' | xargs)
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose -f docker-compose.otlp.yml down --remove-orphans

# Start the OTLP stack
echo "🚀 Starting OTLP stack..."
docker-compose -f docker-compose.otlp.yml up -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be healthy..."

# Wait for OpenSearch
echo "📊 Waiting for OpenSearch..."
timeout 60 bash -c 'until curl -f http://localhost:9200/_cluster/health > /dev/null 2>&1; do sleep 2; done'
echo "✅ OpenSearch is ready!"

# Wait for OTLP Collector
echo "🔍 Waiting for OTLP Collector..."
timeout 60 bash -c 'until curl -f http://localhost:13133/ > /dev/null 2>&1; do sleep 2; done'
echo "✅ OTLP Collector is ready!"

# Wait for OpenSearch Dashboards
echo "📈 Waiting for OpenSearch Dashboards..."
timeout 60 bash -c 'until curl -f http://localhost:5601/api/status > /dev/null 2>&1; do sleep 2; done'
echo "✅ OpenSearch Dashboards is ready!"

echo ""
echo "🎉 OTLP Observability Stack is running!"
echo ""
echo "📊 Services:"
echo "  - OpenSearch: http://localhost:9200"
echo "  - OpenSearch Dashboards: http://localhost:5601"
echo "  - OTLP Collector gRPC: localhost:4317"
echo "  - OTLP Collector HTTP: localhost:4318"
echo "  - OTLP Collector Health: http://localhost:13133"
echo ""
echo "🔑 API Key Validation:"
echo "  - MongoDB: ${MONGODB_URI}"
echo "  - Database: ${MONGODB_DATABASE}"
echo "  - Collection: observabilityIntegrations"
echo ""
echo "🛑 To stop the stack:"
echo "  docker-compose -f docker-compose.otlp.yml down"