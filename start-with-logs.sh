#!/bin/bash

echo "🚀 Starting Application with Observability Stack"

# Start the observability stack
echo "🔧 Starting observability stack (Prometheus + Loki + Jaeger + Grafana)..."
cd monitoring
./start-observability-stack.sh

echo "⏳ Waiting for services to be ready..."
sleep 30

# Start the application
echo "🚀 Starting your application with observability..."
cd ..
npm start

echo "✅ Application with observability stack is running!"
echo ""
echo "📊 Observability Stack:"
echo "  • Logs: App → Winston → Promtail → Loki → Grafana"
echo "  • Metrics: App → Prometheus Client → Prometheus → Grafana"
echo "  • Traces: App → Jaeger Client → Jaeger → Grafana"
echo ""
echo "🔧 Services:"
echo "  • Your App: http://localhost:3000"
echo "  • Prometheus: http://localhost:9090"
echo "  • Loki: http://localhost:3100"
echo "  • Jaeger UI: http://localhost:16686"
echo "  • Grafana: http://localhost:3001 (admin/admin)"
echo ""
echo "✅ All services are running with unified observability!"
echo ""
echo "🌐 Access Points:"
echo "  • Your App: http://localhost:3000"
echo "  • Prometheus: http://localhost:9090"
echo "  • Loki: http://localhost:3100"
echo "  • Jaeger UI: http://localhost:16686"
echo "  • Grafana: http://localhost:3001"
echo ""
echo "📝 Commands:"
echo "  • View app logs: docker-compose logs -f app"
echo "  • View all logs: docker-compose logs"
echo "  • Stop everything: docker-compose down"
echo ""
echo "🎯 Test the pipeline:"
echo "  1. Visit http://localhost:3000 to generate telemetry data"
echo "  2. Check http://localhost:3001 for Grafana dashboard with all 4 panels"
echo "  3. Check http://localhost:16686 for Jaeger traces"
echo "  4. Check http://localhost:5601 for OpenSearch Dashboards"
echo ""
echo "🔄 Send data to OpenSearch:"
echo "  node monitoring/send-to-opensearch.js"
echo ""
echo "ℹ️  Note: All telemetry data flows through the new observability stack (Prometheus + Loki + Jaeger + Grafana + OpenSearch)"