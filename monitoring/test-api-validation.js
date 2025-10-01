#!/usr/bin/env node

// Test script for OTLP API key validation
const axios = require('axios');

const OTLP_ENDPOINT = 'http://localhost:4318/v1/logs';

async function testApiKeyValidation() {
    console.log('🧪 Testing OTLP API Key Validation\n');
    
    // Test 1: Valid API Key
    console.log('✅ Test 1: Valid API Key');
    console.log('=' .repeat(50));
    
    const validApiKey = 'otlp-demo-mern-app-mg7khzdt-za4s11kol';
    
    try {
        const response = await axios.post(OTLP_ENDPOINT, {
            resourceLogs: [{
                resource: {
                    attributes: [{
                        key: 'otlp.api.key',
                        value: validApiKey
                    }, {
                        key: 'service.name',
                        value: 'demo-mern-app'
                    }]
                },
                scopeLogs: [{
                    logRecords: [{
                        timeUnixNano: Date.now() * 1000000,
                        severityNumber: 9,
                        severityText: 'INFO',
                        body: {
                            stringValue: 'Test log message with valid API key'
                        },
                        attributes: [{
                            key: 'log.level',
                            value: 'info'
                        }]
                    }]
                }]
            }]
        }, {
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': validApiKey
            }
        });
        
        console.log(`Status: ${response.status}`);
        console.log('✅ Valid API key accepted - logs forwarded to OpenSearch');
        
    } catch (error) {
        console.log(`❌ Error: ${error.message}`);
    }
    
    console.log('\n');
    
    // Test 2: Invalid API Key
    console.log('❌ Test 2: Invalid API Key');
    console.log('=' .repeat(50));
    
    const invalidApiKey = 'invalid-api-key-12345';
    
    try {
        const response = await axios.post(OTLP_ENDPOINT, {
            resourceLogs: [{
                resource: {
                    attributes: [{
                        key: 'otlp.api.key',
                        value: invalidApiKey
                    }]
                },
                scopeLogs: [{
                    logRecords: [{
                        timeUnixNano: Date.now() * 1000000,
                        severityNumber: 9,
                        severityText: 'INFO',
                        body: {
                            stringValue: 'Test log message with invalid API key'
                        }
                    }]
                }]
            }]
        }, {
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': invalidApiKey
            }
        });
        
        console.log(`Status: ${response.status}`);
        console.log('❌ Invalid API key was accepted (this should not happen)');
        
    } catch (error) {
        console.log(`Status: ${error.response?.status || 'Error'}`);
        console.log('✅ Invalid API key rejected - logs discarded');
    }
    
    console.log('\n✅ API key validation tests completed!');
}

// Run the tests
testApiKeyValidation().catch(console.error);