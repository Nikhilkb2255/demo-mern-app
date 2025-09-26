#!/bin/bash

echo "🚀 Starting Application with Winston + Promtail Observability"

# Start the application with Winston logging and Promtail
echo "🔧 Starting your application with Winston + Promtail observability..."
docker-compose up -d

echo "✅ Application with Winston + Promtail observability is running!"
echo ""
echo "📊 Log Flow:"
echo "  • Your App → Winston → Log Files → Promtail → Loki → Dashboard"
echo ""
echo "🌐 Access Points:"
echo "  • Your App: http://localhost:3000"
echo "  • Local Loki UI: http://localhost:8080 (if running local Loki)"
echo ""
echo "📝 Commands:"
echo "  • View app logs: docker-compose logs -f app"
echo "  • View Promtail logs: docker-compose logs -f promtail"
echo "  • Stop everything: docker-compose down"
echo ""
echo "🎯 Test the pipeline:"
echo "  1. Visit http://localhost:3000 to generate logs"
echo "  2. Check http://localhost:8080 for Loki UI to view logs"
echo ""
echo "ℹ️  Note: Logs flow through Winston → Log Files → Promtail → Loki → Dashboard"