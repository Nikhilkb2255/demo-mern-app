const axios = require('axios');
const { MongoClient } = require('mongodb');
const config = require('./config');

class DataPipeline {
  constructor() {
    this.interval = null;
    this.isRunning = false;
    this.failureCount = 0;
    this.maxFailures = 5;
    this.retryDelay = 5000;
    this.circuitBreakerOpen = false;
    this.lastFailureTime = null;
    this.mongoClient = null;
    
    // Configuration from centralized config
    this.OPENSEARCH_URL = config.OPENSEARCH_URL;
    this.MONGODB_URI = config.MONGODB_URI;
    this.DATABASE_NAME = config.DATABASE_NAME;
    this.COLLECTION_NAME = config.COLLECTION_NAME;
    this.SERVICE_NAME = config.SERVICE_NAME;
    this.maxFailures = config.MAX_FAILURES;
    this.retryDelay = config.RETRY_DELAY;
  }

  async start() {
    if (this.isRunning) {
      console.log('⚠️ Data pipeline is already running');
      return;
    }

    try {
      // Initialize MongoDB connection
      await this.initializeMongoDB();
      
      this.isRunning = true;
      console.log('🚀 Starting data pipeline...');
      
      // Start the interval
      this.interval = setInterval(async () => {
        await this.processData();
      }, config.PIPELINE_INTERVAL);

      // Setup graceful shutdown
      this.setupGracefulShutdown();
      
    } catch (error) {
      console.log('❌ Failed to start data pipeline:', error.message);
      this.isRunning = false;
    }
  }

  async stop() {
    if (!this.isRunning) {
      console.log('⚠️ Data pipeline is not running');
      return;
    }

    console.log('🛑 Stopping data pipeline...');
    
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    
    this.isRunning = false;
    
    // Close MongoDB connection
    if (this.mongoClient) {
      await this.mongoClient.close();
      this.mongoClient = null;
    }
    
    console.log('✅ Data pipeline stopped');
  }

  async initializeMongoDB() {
    try {
      this.mongoClient = new MongoClient(this.MONGODB_URI);
      await this.mongoClient.connect();
      console.log('✅ MongoDB connection established for data pipeline');
    } catch (error) {
      console.log('⚠️ MongoDB connection failed:', error.message);
      // Continue without MongoDB for now
    }
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}, shutting down data pipeline...`);
      await this.stop();
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
  }

  async processData() {
    try {
      // Check circuit breaker
      if (this.circuitBreakerOpen) {
        const timeSinceFailure = Date.now() - this.lastFailureTime;
        if (timeSinceFailure < 60000) { // 1 minute cooldown
          console.log('🔒 Circuit breaker is open, skipping data processing');
          return;
        } else {
          console.log('🔄 Circuit breaker cooldown expired, attempting to reset');
          this.circuitBreakerOpen = false;
          this.failureCount = 0;
        }
      }

      // Validate API key before processing
      const validationResult = await this.validateApiKey();
      if (!validationResult.valid) {
        console.log('⚠️ Invalid API key, skipping data pipeline');
        this.handleFailure('Invalid API key');
        return;
      }

      console.log('🚀 Processing observability data...');
      
      // Process all data types
      await this.sendLogsToOpenSearch(validationResult.context);
      await this.sendMetricsToOpenSearch(validationResult.context);
      await this.sendTracesToOpenSearch(validationResult.context);
      
      // Reset failure count on success
      this.failureCount = 0;
      console.log('✅ Data pipeline completed successfully');
      
    } catch (error) {
      console.log('⚠️ Data pipeline error:', error.message);
      this.handleFailure(error.message);
    }
  }

  async validateApiKey() {
    try {
      const apiKey = process.env.OBSERVABILITY_API_KEY;
      const organisationId = process.env.ORGANISATION_ID;
      const projectId = process.env.PROJECT_ID;

      if (!apiKey || !organisationId || !projectId) {
        return {
          valid: false,
          reason: 'Missing required environment variables'
        };
      }

      // If MongoDB is not available, use basic validation
      if (!this.mongoClient) {
        console.log('⚠️ MongoDB not available, using basic API key validation');
        return {
          valid: apiKey.length >= 8, // Basic length check
          context: {
            apiKey: apiKey.substring(0, 8) + '...',
            organisationId,
            projectId,
            repositoryUrl: process.env.REPOSITORY_URL,
            serviceName: this.SERVICE_NAME
          }
        };
      }

      // MongoDB validation using observabilityIntegrations collection
      const db = this.mongoClient.db(this.DATABASE_NAME);
      const collection = db.collection(this.COLLECTION_NAME);
      
      const integration = await collection.findOne({
        observabilityApiKey: apiKey,
        organisationID: organisationId,
        projectID: projectId,
        status: 'active',
        isDeleted: false
      });

      if (!integration) {
        return {
          valid: false,
          reason: 'API key not found or inactive'
        };
      }

      return {
        valid: true,
        context: {
          apiKey: apiKey.substring(0, 8) + '...',
          organisationId,
          projectId,
          repositoryUrl: integration.repositoryUrl || process.env.REPOSITORY_URL,
          serviceName: integration.serviceName || this.SERVICE_NAME,
          projectName: integration.projectName,
          integrationType: integration.integrationType,
          integrationId: integration._id,
          integrationDate: integration.integrationDate
        }
      };

    } catch (error) {
      console.log('⚠️ API key validation failed:', error.message);
      return {
        valid: false,
        reason: 'Validation error: ' + error.message
      };
    }
  }

  handleFailure(errorMessage) {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    console.log(`⚠️ Data pipeline failure ${this.failureCount}/${this.maxFailures}: ${errorMessage}`);
    
    if (this.failureCount >= this.maxFailures) {
      this.circuitBreakerOpen = true;
      console.log('🚨 Circuit breaker activated - data pipeline paused');
    }
  }

  async sendLogsToOpenSearch(context) {
    try {
      const lokiResponse = await axios.get('http://loki:3100/loki/api/v1/query_range', {
        params: {
          query: `{job="${this.SERVICE_NAME}"}`,
          start: Math.floor(Date.now() / 1000) - 60, // Last minute
          end: Math.floor(Date.now() / 1000)
        }
      });

      if (lokiResponse.data.data.result.length > 0) {
        const logs = lokiResponse.data.data.result[0].values;
        
        for (const log of logs.slice(-3)) { // Send last 3 logs
          const logData = {
            timestamp: new Date(parseInt(log[0]) / 1000000).toISOString(),
            message: log[1],
            service: context.serviceName,
            data_type: 'logs',
            source: 'loki',
            repository_url: context.repositoryUrl,
            organisation_id: context.organisationId,
            project_id: context.projectId,
            project_name: context.projectName,
            integration_type: context.integrationType,
            api_key: context.apiKey,
            integration_id: context.integrationId,
            integration_date: context.integrationDate
          };

          await axios.post(`${this.OPENSEARCH_URL}/application-logs/_doc`, logData);
          console.log('✅ Sent log to OpenSearch:', logData.message.substring(0, 50) + '...');
        }
      }
    } catch (error) {
      console.log('⚠️ Could not send logs to OpenSearch:', error.message);
      throw error;
    }
  }

  async sendMetricsToOpenSearch(context) {
    try {
      const prometheusResponse = await axios.get('http://prometheus:9090/api/v1/query', {
        params: {
          query: 'http_requests_total'
        }
      });

      if (prometheusResponse.data.data.result.length > 0) {
        const metric = prometheusResponse.data.data.result[0];
        const metricData = {
          timestamp: new Date().toISOString(),
          metric_name: metric.metric.__name__,
          metric_value: parseFloat(metric.value[1]),
          labels: metric.metric,
          service: context.serviceName,
          data_type: 'metrics',
          source: 'prometheus',
          repository_url: context.repositoryUrl,
          organisation_id: context.organisationId,
          project_id: context.projectId,
          project_name: context.projectName,
          integration_type: context.integrationType,
          api_key: context.apiKey,
          integration_id: context.integrationId,
          integration_date: context.integrationDate
        };

        await axios.post(`${this.OPENSEARCH_URL}/application-metrics/_doc`, metricData);
        console.log('✅ Sent metric to OpenSearch:', metricData.metric_name);
      }
    } catch (error) {
      console.log('⚠️ Could not send metrics to OpenSearch:', error.message);
      throw error;
    }
  }

  async sendTracesToOpenSearch(context) {
    try {
      const jaegerResponse = await axios.get('http://jaeger:16686/api/traces', {
        params: {
          service: context.serviceName,
          limit: 3
        }
      });

      if (jaegerResponse.data.data.length > 0) {
        for (const trace of jaegerResponse.data.data.slice(0, 3)) {
          const traceData = {
            timestamp: new Date().toISOString(),
            trace_id: trace.traceID,
            spans: trace.spans.length,
            duration: trace.duration,
            service: context.serviceName,
            data_type: 'traces',
            source: 'jaeger',
            repository_url: context.repositoryUrl,
            organisation_id: context.organisationId,
            project_id: context.projectId,
            project_name: context.projectName,
            integration_type: context.integrationType,
            api_key: context.apiKey,
            integration_id: context.integrationId,
            integration_date: context.integrationDate
          };

          await axios.post(`${this.OPENSEARCH_URL}/jaeger-traces/_doc`, traceData);
          console.log('✅ Sent trace to OpenSearch:', traceData.trace_id, 'with', traceData.spans, 'spans');
        }
      }
    } catch (error) {
      console.log('⚠️ Could not send traces to OpenSearch:', error.message);
      throw error;
    }
  }

  // Health check method
  getStatus() {
    return {
      isRunning: this.isRunning,
      failureCount: this.failureCount,
      circuitBreakerOpen: this.circuitBreakerOpen,
      lastFailureTime: this.lastFailureTime,
      mongoConnected: !!this.mongoClient
    };
  }
}

module.exports = DataPipeline;