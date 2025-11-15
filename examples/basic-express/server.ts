/**
 * Basic Express Server with Qiuth Authentication
 * 
 * This example demonstrates how to use Qiuth middleware to protect Express routes
 * with multi-factor authentication.
 */

import express from 'express';
import { createQiuthMiddleware, QiuthConfigBuilder, generateApiKey, generateTotpSecret } from '../../src';

const app = express();
app.use(express.json());

// Generate credentials (in production, load from secure storage)
const apiKey = generateApiKey();
const totpSecret = generateTotpSecret();

console.log('='.repeat(60));
console.log('Qiuth Basic Express Example');
console.log('='.repeat(60));
console.log('API Key:', apiKey);
console.log('TOTP Secret:', totpSecret);
console.log('='.repeat(60));
console.log('\nServer starting on http://localhost:3000');
console.log('\nTest with curl:');
console.log(`curl -H "X-API-Key: ${apiKey}" http://localhost:3000/api/public`);
console.log('='.repeat(60));

// Create Qiuth configuration
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withIpAllowlist(['0.0.0.0/0']) // Allow all IPs for demo
  .build();

// Create Qiuth middleware
const qiuthAuth = createQiuthMiddleware({
  config,
  extractApiKey: (req) => {
    // Extract API key from header
    return req.headers['x-api-key'] as string;
  },
  extractClientIp: (req) => {
    // Extract client IP (handles proxies)
    return (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || req.socket.remoteAddress || '';
  },
  onSuccess: (req, res, result) => {
    console.log(`✓ Authentication successful for ${req.path}`);
  },
  onFailure: (req, res, result) => {
    console.error(`✗ Authentication failed for ${req.path}:`, result.errors);
  },
});

// Public route (no authentication)
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Qiuth Basic Express Example',
    endpoints: {
      public: '/api/public',
      protected: '/api/protected',
      user: '/api/user',
    },
    authentication: {
      apiKey: 'Required for all /api/* routes',
      header: 'X-API-Key',
    },
  });
});

// Protected routes
app.get('/api/public', qiuthAuth, (req, res) => {
  res.json({
    message: 'This is a public API endpoint (but still requires authentication)',
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/protected', qiuthAuth, (req, res) => {
  res.json({
    message: 'This is a protected API endpoint',
    data: {
      secret: 'This data is only accessible with valid authentication',
      timestamp: new Date().toISOString(),
    },
  });
});

app.get('/api/user', qiuthAuth, (req, res) => {
  res.json({
    message: 'User information',
    user: {
      id: '12345',
      name: 'Service Account',
      permissions: ['read', 'write'],
    },
  });
});

app.post('/api/data', qiuthAuth, (req, res) => {
  res.json({
    message: 'Data received',
    received: req.body,
    timestamp: new Date().toISOString(),
  });
});

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n✓ Server is running on http://localhost:${PORT}`);
  console.log('\nTry these commands:');
  console.log(`\n1. Public endpoint (requires auth):`);
  console.log(`   curl -H "X-API-Key: ${apiKey}" http://localhost:${PORT}/api/public`);
  console.log(`\n2. Protected endpoint:`);
  console.log(`   curl -H "X-API-Key: ${apiKey}" http://localhost:${PORT}/api/protected`);
  console.log(`\n3. POST data:`);
  console.log(`   curl -X POST -H "X-API-Key: ${apiKey}" -H "Content-Type: application/json" -d '{"test":"data"}' http://localhost:${PORT}/api/data`);
  console.log(`\n4. Without API key (should fail):`);
  console.log(`   curl http://localhost:${PORT}/api/public`);
  console.log('\n');
});

