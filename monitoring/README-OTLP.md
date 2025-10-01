# OTLP Collector with MongoDB API Key Validation

This directory contains the complete OTLP (OpenTelemetry Protocol) observability stack with MongoDB-based API key validation.

## 🏗️ Architecture

```
Application → Winston → OTLP Collector → MongoDB Validation → OpenSearch → Dashboards
```

## 📁 Files

- `otel-collector-config.yaml` - OTLP Collector configuration
- `docker-compose.otlp.yml` - Docker Compose for the entire stack
- `start-otlp-stack.sh` - Startup script for the entire stack
- `test-api-validation.js` - Test script for API key validation
- `env.otlp` - Environment variables

## 🚀 Quick Start

1. **Start the OTLP Stack**:
   ```bash
   cd monitoring
   ./start-otlp-stack.sh
   ```

2. **Test API Key Validation**:
   ```bash
   node test-api-validation.js
   ```

3. **View Logs in OpenSearch Dashboards**:
   - Open http://localhost:5601
   - Create index pattern: `otlp-logs`
   - View real-time logs

## 🔑 API Key Validation Process

### 1. Log Collection
- Winston logger sends logs to OTLP Collector
- Logs include API key in resource attributes or headers

### 2. API Key Extraction
The OTLP Collector extracts API keys from:
- HTTP Headers: `X-API-Key`, `Authorization`
- Resource Attributes: `otlp.api.key`, `api.key`
- Log Metadata: Custom attributes

### 3. MongoDB Validation
```javascript
// Validation query
{
  otlpApiKey: "extracted-api-key",
  status: "active",
  isDeleted: false
}
```

### 4. Decision Making
- ✅ **Valid API Key**: Logs forwarded to OpenSearch
- ❌ **Invalid API Key**: Logs discarded
- 🔍 **Caching**: Valid API keys cached for 5 minutes

## 🛠️ Configuration

### Environment Variables
```bash
# OTLP Collector
OTLP_ENDPOINT=http://otel-collector:4318/v1/logs
OTLP_GRPC_ENDPOINT=otel-collector:4317

# MongoDB
MONGODB_URI=mongodb://devopsark-dev:password@mongo-node-one.devopsark.cloud:37123
MONGODB_DATABASE=devopsark-dev

# OpenSearch
OPENSEARCH_ENDPOINT=http://opensearch:9200
OPENSEARCH_INDEX=otlp-logs
```

## 🧪 Testing

### Test Valid API Key
```bash
curl -X POST http://localhost:4318/v1/logs \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: otlp-demo-mern-app-mg7khzdt-za4s11kol' \
  -d '{
    "resourceLogs": [{
      "resource": {
        "attributes": [{
          "key": "otlp.api.key",
          "value": "otlp-demo-mern-app-mg7khzdt-za4s11kol"
        }]
      },
      "scopeLogs": [{
        "logRecords": [{
          "timeUnixNano": 1640995200000000000,
          "severityNumber": 9,
          "severityText": "INFO",
          "body": {
            "stringValue": "Test log message"
          }
        }]
      }]
    }]
  }'
```

### Test Invalid API Key
```bash
curl -X POST http://localhost:4318/v1/logs \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: invalid-key' \
  -d '{"resourceLogs": []}'
```

## 📊 Monitoring

### Health Checks
- OTLP Collector: http://localhost:13133
- OpenSearch: http://localhost:9200/_cluster/health
- OpenSearch Dashboards: http://localhost:5601/api/status

### Logs
```bash
# OTLP Collector logs
docker logs devopsark-otel-collector

# OpenSearch logs
docker logs devopsark-opensearch

# All services
docker-compose -f docker-compose.otlp.yml logs
```

## 🛑 Stopping the Stack

```bash
docker-compose -f docker-compose.otlp.yml down
```

## 📚 References

- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- [OpenSearch](https://opensearch.org/docs/)
- [OTLP Protocol](https://opentelemetry.io/docs/specs/otlp/)