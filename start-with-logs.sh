#!/bin/bash

echo "🚀 Starting Application with Winston + OTLP Collector + OpenSearch Observability"

# Start the application with Winston logging and OTLP Collector
echo "🔧 Starting your application with Winston + OTLP Collector + OpenSearch observability..."
docker-compose up -d

echo "✅ Application with Winston + OTLP Collector + OpenSearch observability is running!"
echo ""
echo "📊 Log Flow:"
echo "  • Your App → Winston → OTLP Collector → MongoDB Validation → OpenSearch → Dashboard"
echo ""
echo "🌐 Access Points:"
echo "  • Your App: http://localhost:3000"
echo "  • OpenSearch: http://localhost:9200"
echo "  • OpenSearch Dashboards: http://localhost:5601"
echo "  • OTLP Collector Health: http://localhost:13133"
echo ""
echo "📝 Commands:"
echo "  • View app logs: docker-compose logs -f app"
echo "  • View OTLP Collector logs: docker-compose logs -f otel-collector"
echo "  • Stop everything: docker-compose down"
echo ""
echo "🎯 Test the pipeline:"
echo "  1. Visit http://localhost:3000 to generate logs"
echo "  2. Check http://localhost:5601 for OpenSearch Dashboards to view logs"
echo "  3. Check http://localhost:13133 for OTLP Collector health"
echo ""
echo "ℹ️  Note: Logs flow through Winston → OTLP Collector → MongoDB Validation → OpenSearch → Dashboard"