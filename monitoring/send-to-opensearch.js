#!/usr/bin/env node

// Manual script to send observability data to OpenSearch
// This script is automatically created during observability integration

const axios = require('axios');

const OPENSEARCH_URL = process.env.OPENSEARCH_URL || 'http://localhost:9200';

async function sendLogsToOpenSearch() {
    try {
        // Get logs from Loki
        const lokiResponse = await axios.get('http://localhost:3100/loki/api/v1/query_range', {
            params: {
                query: '{job="demo-mern-app"}',
                start: Math.floor(Date.now() / 1000) - 3600, // Last hour
                end: Math.floor(Date.now() / 1000)
            }
        });

        if (lokiResponse.data.data.result.length > 0) {
            const logs = lokiResponse.data.data.result[0].values;
            
            for (const log of logs.slice(-5)) { // Send last 5 logs
                const logData = {
                    timestamp: new Date(parseInt(log[0]) / 1000000).toISOString(),
                    message: log[1],
                    service: process.env.SERVICE_NAME || 'demo-mern-app',
                    data_type: 'logs',
                    source: 'loki',
                    repository_url: process.env.REPOSITORY_URL,
                    organisation_id: process.env.ORGANISATION_ID,
                    project_id: process.env.PROJECT_ID
                };

                await axios.post(`${OPENSEARCH_URL}/application-logs/_doc`, logData);
                console.log('✅ Sent log to OpenSearch:', logData.message.substring(0, 50) + '...');
            }
        }
    } catch (error) {
        console.log('⚠️  Could not fetch logs from Loki:', error.message);
    }
}

async function sendMetricsToOpenSearch() {
    try {
        // Get metrics from Prometheus
        const prometheusResponse = await axios.get('http://localhost:9090/api/v1/query', {
            params: {
                query: 'http_requests_total'
            }
        });

        if (prometheusResponse.data.data.result.length > 0) {
            const metric = prometheusResponse.data.data.result[0];
            const metricData = {
                timestamp: new Date().toISOString(),
                metric_name: metric.metric.__name__,
                value: metric.value[1],
                labels: metric.metric,
                service: process.env.SERVICE_NAME || 'demo-mern-app',
                data_type: 'metrics',
                source: 'prometheus',
                repository_url: process.env.REPOSITORY_URL,
                organisation_id: process.env.ORGANISATION_ID,
                project_id: process.env.PROJECT_ID
            };

            await axios.post(`${OPENSEARCH_URL}/prometheus-metrics/_doc`, metricData);
            console.log('✅ Sent metric to OpenSearch:', metricData.metric_name, '=', metricData.value);
        }
    } catch (error) {
        console.log('⚠️  Could not fetch metrics from Prometheus:', error.message);
    }
}

async function sendTracesToOpenSearch() {
    try {
        // Get traces from Jaeger
        const jaegerResponse = await axios.get('http://localhost:16686/api/traces', {
            params: {
                service: process.env.SERVICE_NAME || 'demo-mern-app',
                limit: 5
            }
        });

        if (jaegerResponse.data.data.length > 0) {
            for (const trace of jaegerResponse.data.data.slice(0, 3)) {
                const traceData = {
                    timestamp: new Date().toISOString(),
                    trace_id: trace.traceID,
                    spans: trace.spans.length,
                    duration: trace.duration,
                    service: process.env.SERVICE_NAME || 'demo-mern-app',
                    data_type: 'traces',
                    source: 'jaeger',
                    repository_url: process.env.REPOSITORY_URL,
                    organisation_id: process.env.ORGANISATION_ID,
                    project_id: process.env.PROJECT_ID
                };

                await axios.post(`${OPENSEARCH_URL}/jaeger-traces/_doc`, traceData);
                console.log('✅ Sent trace to OpenSearch:', traceData.trace_id, 'with', traceData.spans, 'spans');
            }
        }
    } catch (error) {
        console.log('⚠️  Could not fetch traces from Jaeger:', error.message);
    }
}

async function main() {
    console.log('🚀 Sending observability data to OpenSearch...\n');
    
    await sendLogsToOpenSearch();
    await sendMetricsToOpenSearch();
    await sendTracesToOpenSearch();
    
    console.log('\n🎉 All data sent to OpenSearch!');
    console.log('\n📊 Data is now stored in OpenSearch indices');
    console.log('\n🌐 Access OpenSearch Dashboards: http://localhost:5601');
    console.log('📊 Check OpenSearch indices: http://localhost:9200/_cat/indices?v');
}

main().catch(console.error);