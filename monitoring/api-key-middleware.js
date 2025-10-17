// API Key Validation Middleware for Observability
const crypto = require('crypto');

// Generate a secure API key
const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Validate API key against MongoDB
const validateApiKey = async (req, res, next) => {
  const apiKey = req.headers['authorization'];
  
  // Check if API key is provided
  if (!apiKey) {
    return res.status(401).json({ 
      error: 'Unauthorized',
      message: 'API key is required',
      timestamp: new Date().toISOString()
    });
  }
  
  // Check if API key format is correct (Bearer token)
  if (!apiKey.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Unauthorized',
      message: 'Invalid API key format. Use "Bearer <api_key>"',
      timestamp: new Date().toISOString()
    });
  }
  
  // Extract the actual API key
  const providedApiKey = apiKey.substring(7); // Remove "Bearer " prefix
  
  try {
    // Validate API key against MongoDB
    const validationResult = await validateObservabilityApiKey(providedApiKey);
    
    if (!validationResult.valid) {
      return res.status(401).json({ 
        error: 'Unauthorized',
        message: validationResult.message,
        timestamp: new Date().toISOString()
      });
    }
    
    // Add API key and user context to request for downstream processing
    req.observabilityApiKey = providedApiKey;
    req.integrationId = validationResult.integration._id;
    req.repositoryUrl = validationResult.integration.repositoryUrl;
    req.projectName = validationResult.integration.projectName;
    req.organisationID = validationResult.integration.organisationID;
    req.projectID = validationResult.integration.projectID;
    
    next();
  } catch (error) {
    console.error('API key validation error:', error);
    return res.status(500).json({ 
      error: 'Internal Server Error',
      message: 'Failed to validate API key',
      timestamp: new Date().toISOString()
    });
  }
};

// MongoDB API key validation function
async function validateObservabilityApiKey(apiKey) {
  const { MongoClient } = require('mongodb');
  
  try {
    const client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017');
    await client.connect();
    
    const db = client.db(process.env.devopsarkDatabaseName || 'devopsark-dev');
    
    const integration = await db.collection('observabilityIntegrations')
      .findOne({ 
        observabilityApiKey: apiKey,
        status: 'active',
        isDeleted: false 
      });
    
    await client.close();
    
    if (!integration) {
      return {
        valid: false,
        message: 'Invalid API key'
      };
    }
    
    return {
      valid: true,
      integration: {
        _id: integration._id,
        objectID: integration.objectID,
        repositoryUrl: integration.repositoryUrl,
        projectName: integration.projectName,
        organisationID: integration.organisationID,
        projectID: integration.projectID,
        apiKeyGeneratedAt: integration.apiKeyGeneratedAt
      },
      message: 'API key is valid'
    };
  } catch (error) {
    console.error('MongoDB validation error:', error);
    return {
      valid: false,
      message: 'Failed to validate API key'
    };
  }
}

// Middleware to add API key to all observability data
const addApiKeyToData = (req, res, next) => {
  // Store original res.json
  const originalJson = res.json;
  
  // Override res.json to add API key to response data
  res.json = function(data) {
    if (data && typeof data === 'object') {
      data.api_key = req.observabilityApiKey;
      data.timestamp = new Date().toISOString();
    }
    return originalJson.call(this, data);
  };
  
  next();
};

// Middleware for observability endpoints
const observabilityMiddleware = (req, res, next) => {
  // Add API key validation for observability endpoints
  if (req.path.includes('/metrics') || 
      req.path.includes('/logs') || 
      req.path.includes('/traces') ||
      req.path.includes('/observability')) {
    return validateApiKey(req, res, next);
  }
  next();
};

// Middleware to log API key usage
const logApiKeyUsage = (req, res, next) => {
  if (req.observabilityApiKey) {
    console.log(`[API Key Usage] ${req.method} ${req.path} - API Key: ${req.observabilityApiKey.substring(0, 8)}...`);
  }
  next();
};

module.exports = {
  generateApiKey,
  validateApiKey,
  addApiKeyToData,
  observabilityMiddleware,
  logApiKeyUsage
};