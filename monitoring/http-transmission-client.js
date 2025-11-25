const axios = require('axios');
const config = require('./config');

class ObservabilityHttpClient {
  constructor() {
    this.backendUrl = config.BACKEND_URL || 'http://localhost:4000';
    this.apiKey = process.env.OBSERVABILITY_API_KEY;
    this.organisationId = process.env.ORGANISATION_ID;
    this.projectId = process.env.PROJECT_ID;
    this.serviceName = config.SERVICE_NAME;
    this.serviceVersion = config.SERVICE_VERSION;
    this.repositoryUrl = process.env.REPOSITORY_URL;
    
    // HTTP client configuration
    this.httpClient = axios.create({
      baseURL: this.backendUrl,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `${this.serviceName}/${this.serviceVersion}`,
        'X-API-Key': this.apiKey,
        'X-Organisation-ID': this.organisationId,
        'X-Project-ID': this.projectId
      }
    });

    // Retry configuration
    this.maxRetries = 3;
    this.retryDelay = 1000;
    this.circuitBreakerOpen = false;
    this.failureCount = 0;
    this.maxFailures = 5;
    this.lastFailureTime = null;
  }

  async sendLogs(logs) {
    try {
      if (this.circuitBreakerOpen) {
        console.log('🔒 Circuit breaker is open, skipping log transmission');
        return false;
      }

      const payload = {
        data_type: 'logs',
        service: this.serviceName,
        version: this.serviceVersion,
        repository_url: this.repositoryUrl,
        organisation_id: this.organisationId,
        project_id: this.projectId,
        logs: Array.isArray(logs) ? logs : [logs],
        timestamp: new Date().toISOString()
      };

      const response = await this.httpClient.post('/v1/observability/logs', payload);
      console.log('✅ Logs sent successfully:', response.status);
      this.resetFailureCount();
      return true;

    } catch (error) {
      console.error('❌ Failed to send logs:', error.message);
      this.handleFailure();
      return false;
    }
  }

  async sendMetrics(metrics) {
    try {
      if (this.circuitBreakerOpen) {
        console.log('🔒 Circuit breaker is open, skipping metrics transmission');
        return false;
      }

      const payload = {
        data_type: 'metrics',
        service: this.serviceName,
        version: this.serviceVersion,
        repository_url: this.repositoryUrl,
        organisation_id: this.organisationId,
        project_id: this.projectId,
        metrics: Array.isArray(metrics) ? metrics : [metrics],
        timestamp: new Date().toISOString()
      };

      const response = await this.httpClient.post('/v1/observability/metrics', payload);
      console.log('✅ Metrics sent successfully:', response.status);
      this.resetFailureCount();
      return true;

    } catch (error) {
      console.error('❌ Failed to send metrics:', error.message);
      this.handleFailure();
      return false;
    }
  }

  async sendTraces(traces) {
    try {
      if (this.circuitBreakerOpen) {
        console.log('🔒 Circuit breaker is open, skipping traces transmission');
        return false;
      }

      const payload = {
        data_type: 'traces',
        service: this.serviceName,
        version: this.serviceVersion,
        repository_url: this.repositoryUrl,
        organisation_id: this.organisationId,
        project_id: this.projectId,
        traces: Array.isArray(traces) ? traces : [traces],
        timestamp: new Date().toISOString()
      };

      const response = await this.httpClient.post('/v1/observability/traces', payload);
      console.log('✅ Traces sent successfully:', response.status);
      this.resetFailureCount();
      return true;

    } catch (error) {
      console.error('❌ Failed to send traces:', error.message);
      this.handleFailure();
      return false;
    }
  }

  async sendHealthStatus(status) {
    try {
      const payload = {
        data_type: 'health',
        service: this.serviceName,
        version: this.serviceVersion,
        repository_url: this.repositoryUrl,
        organisation_id: this.organisationId,
        project_id: this.projectId,
        status: status,
        timestamp: new Date().toISOString()
      };

      const response = await this.httpClient.post('/v1/observability/health', payload);
      console.log('✅ Health status sent successfully:', response.status);
      return true;

    } catch (error) {
      console.error('❌ Failed to send health status:', error.message);
      return false;
    }
  }

  async sendBatch(batchData) {
    try {
      if (this.circuitBreakerOpen) {
        console.log('🔒 Circuit breaker is open, skipping batch transmission');
        return false;
      }

      const payload = {
        service: this.serviceName,
        version: this.serviceVersion,
        repository_url: this.repositoryUrl,
        organisation_id: this.organisationId,
        project_id: this.projectId,
        ...batchData,
        timestamp: new Date().toISOString()
      };

      const response = await this.httpClient.post('/v1/observability/batch', payload);
      console.log('✅ Batch data sent successfully:', response.status);
      this.resetFailureCount();
      return true;

    } catch (error) {
      console.error('❌ Failed to send batch data:', error.message);
      this.handleFailure();
      return false;
    }
  }

  async validateConnection() {
    try {
      const response = await this.httpClient.get('/v1/observability/validate');
      console.log('✅ Backend connection validated:', response.status);
      return true;
    } catch (error) {
      console.error('❌ Backend connection validation failed:', error.message);
      return false;
    }
  }

  handleFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    console.log(`⚠️ Transmission failure ${this.failureCount}/${this.maxFailures}`);
    
    if (this.failureCount >= this.maxFailures) {
      this.circuitBreakerOpen = true;
      console.log('🚨 Circuit breaker activated - HTTP transmission paused');
      
      // Reset circuit breaker after 5 minutes
      setTimeout(() => {
        this.circuitBreakerOpen = false;
        this.failureCount = 0;
        console.log('🔄 Circuit breaker reset - HTTP transmission resumed');
      }, 300000); // 5 minutes
    }
  }

  resetFailureCount() {
    this.failureCount = 0;
    this.circuitBreakerOpen = false;
  }

  getStatus() {
    return {
      backendUrl: this.backendUrl,
      circuitBreakerOpen: this.circuitBreakerOpen,
      failureCount: this.failureCount,
      lastFailureTime: this.lastFailureTime,
      serviceName: this.serviceName,
      organisationId: this.organisationId,
      projectId: this.projectId
    };
  }
}

module.exports = ObservabilityHttpClient;