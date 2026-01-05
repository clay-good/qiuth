#!/usr/bin/env ts-node
/**
 * Qiuth Interactive Demo Server
 * 
 * This demo shows all three security layers in action:
 * 1. IP Allowlisting - First line of defense
 * 2. TOTP MFA - Time-based one-time passwords for service accounts
 * 3. Certificate Auth - Cryptographic proof of private key possession
 * 
 * Run: npm run demo
 */

import express, { Request, Response } from 'express';
import {
  QiuthConfigBuilder,
  createQiuthMiddleware,
  generateApiKey,
  generateTotpSecret,
  generateKeyPair,
  TotpValidator,
  CertificateValidator
} from '../src/index';

const app = express();
app.use(express.json());

// Generate demo credentials
const apiKey = generateApiKey();
const totpSecret = generateTotpSecret();
const { publicKey, privateKey } = generateKeyPair({ modulusLength: 2048 });

console.log('\n' + '='.repeat(80));
console.log('🔐 QIUTH INTERACTIVE DEMO - Multi-Factor Authentication for API Keys');
console.log('='.repeat(80));
console.log('\n📋 DEMO CREDENTIALS (save these for testing):');
console.log('─'.repeat(80));
console.log(`API Key:        ${apiKey}`);
console.log(`TOTP Secret:    ${totpSecret}`);
console.log(`Current Token:  ${getCurrentTotp()} (changes every 30 seconds)`);
console.log(`\nPrivate Key:\n${privateKey}`);
console.log(`\nPublic Key:\n${publicKey}`);
console.log('─'.repeat(80));

// Create configurations for different security levels
const configs = {
  // Level 1: Just API Key
  basic: new QiuthConfigBuilder()
    .withApiKey(apiKey)
    .build(),
  
  // Level 2: API Key + IP Allowlist
  withIp: new QiuthConfigBuilder()
    .withApiKey(apiKey)
    .withIpAllowlist(['127.0.0.1', '::1', '::ffff:127.0.0.1']) // localhost
    //.withIpAllowlist(['192.168.90.1']) 
    .build(),
  
  // Level 3: API Key + IP + TOTP
  withTotp: new QiuthConfigBuilder()
    .withApiKey(apiKey)
    .withIpAllowlist(['127.0.0.1', '::1', '::ffff:127.0.0.1'])
    .withTotp(totpSecret, 30, 1)
    .build(),
  
  // Level 4: All three layers (Maximum Security)
  full: new QiuthConfigBuilder()
    .withApiKey(apiKey)
    .withIpAllowlist(['127.0.0.1', '::1', '::ffff:127.0.0.1'])
    .withTotp(totpSecret, 30, 1)
    .withCertificate(publicKey, 300)
    .build(),
};

// Helper to generate current TOTP token
function getCurrentTotp(): string {
  const validator = new TotpValidator({ 
    enabled: true, 
    secret: totpSecret, 
    timeStep: 30, 
    window: 1 
  });
  return validator.generate();
}

// Helper to sign a request
function signRequest(method: string, url: string, body: string = ''): { timestamp: string; signature: string } {
  const timestamp = Date.now();
  const signature = CertificateValidator.sign(privateKey, method, url, body, timestamp);
  return { timestamp: timestamp.toString(), signature };
}

// Root endpoint - Demo instructions
app.get('/', (_req: Request, res: Response) => {
  const currentTotp = getCurrentTotp();
  const { timestamp, signature } = signRequest('GET', 'http://localhost:3000/api/full', '');
  
  res.json({
    message: '🔐 Qiuth Interactive Demo',
    description: 'Test multi-factor authentication for API keys',
    
    credentials: {
      apiKey,
      totpSecret,
      currentTotp,
      note: 'TOTP changes every 30 seconds'
    },
    
    endpoints: {
      '/api/basic': 'Level 1: API Key only',
      '/api/with-ip': 'Level 2: API Key + IP Allowlist',
      '/api/with-totp': 'Level 3: API Key + IP + TOTP',
      '/api/full': 'Level 4: All three layers (Maximum Security)',
      '/api/data': 'POST endpoint with full security',
      '/health': 'Health check (no auth)',
    },
    
    testCommands: {
      '1_basic': `curl -H "X-API-Key: ${apiKey}" http://localhost:3000/api/basic`,
      
      '2_with_ip': `curl -H "X-API-Key: ${apiKey}" http://localhost:3000/api/with-ip`,
      
      '3_with_totp': `curl -H "X-API-Key: ${apiKey}" -H "X-TOTP-Token: ${currentTotp}" http://localhost:3000/api/with-totp`,
      
      '4_full_security': `curl -H "X-API-Key: ${apiKey}" -H "X-TOTP-Token: ${currentTotp}" -H "X-Timestamp: ${timestamp}" -H "X-Signature: ${signature}" http://localhost:3000/api/full`,
      
      '5_post_data': `curl -X POST -H "X-API-Key: ${apiKey}" -H "X-TOTP-Token: ${currentTotp}" -H "Content-Type: application/json" -d '{"test":"data"}' http://localhost:3000/api/data`,
      
      '6_fail_wrong_key': `curl -H "X-API-Key: wrong-key" http://localhost:3000/api/basic`,
      
      '7_fail_no_totp': `curl -H "X-API-Key: ${apiKey}" http://localhost:3000/api/with-totp`,
    },
    
    interactiveHelpers: {
      getCurrentTotp: 'GET /totp/current',
      signRequest: 'POST /sign with { method, url, body }',
    }
  });
});

// Helper endpoints
app.get('/totp/current', (_req: Request, res: Response) => {
  const token = getCurrentTotp();
  res.json({
    token,
    expiresIn: '30 seconds',
    secret: totpSecret,
    note: `Use the 6-digit token (${token}), NOT the secret, in X-TOTP-Token header`,
  });
});

app.post('/sign', (req: Request, res: Response) => {
  const { method = 'GET', url = 'http://localhost:3000/api/full', body } = req.body;

  // For GET requests, Express creates an empty object {} even when there's no body
  // So we need to sign with "{}" to match what the middleware will see
  let bodyToSign: string;
  if (body === undefined || body === null || body === '') {
    // For GET requests with no body, Express will have req.body = {}
    // which gets serialized to "{}"
    bodyToSign = method.toUpperCase() === 'GET' ? '{}' : '';
  } else if (typeof body === 'string') {
    bodyToSign = body;
  } else {
    bodyToSign = JSON.stringify(body);
  }

  const { timestamp, signature } = signRequest(method, url, bodyToSign);
  res.json({ timestamp, signature, method, url, bodyUsed: bodyToSign });
});

// Health check (no auth)
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Debug endpoint to see what URL the server constructs
app.get('/debug/url', (req: Request, res: Response) => {
  const protocol = req.protocol;
  const host = req.get('host') || 'localhost';
  const path = req.originalUrl || req.url;
  const fullUrl = `${protocol}://${host}${path}`;

  res.json({
    protocol,
    host,
    path,
    fullUrl,
    ip: req.ip,
    headers: req.headers,
  });
});

// Debug endpoint to test signature verification
app.get('/debug/verify', (req: Request, res: Response) => {
  const method = req.method;
  const protocol = req.protocol;
  const host = req.get('host') || 'localhost';
  const path = req.originalUrl || req.url;
  const fullUrl = `${protocol}://${host}${path}`;
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const body = req.body;

  // Get body as middleware would
  let bodyForValidation: string | undefined;
  if (!body) {
    bodyForValidation = undefined;
  } else if (Buffer.isBuffer(body)) {
    bodyForValidation = body.toString();
  } else if (typeof body === 'string') {
    bodyForValidation = body;
  } else {
    bodyForValidation = JSON.stringify(body);
  }

  // Try to verify
  const validator = new CertificateValidator({
    enabled: true,
    publicKey,
    maxAge: 300,
  });

  const isValid = validator.verify(
    signature as string,
    method,
    fullUrl,
    bodyForValidation,
    timestamp as string
  );

  res.json({
    method,
    fullUrl,
    timestamp,
    body: bodyForValidation,
    bodyType: typeof body,
    bodyIsUndefined: body === undefined,
    signature: signature ? `${String(signature).substring(0, 50)}...` : null,
    isValid,
    publicKeyPreview: publicKey.substring(0, 100) + '...',
  });
});

// Create middleware for each security level
const basicAuth = createQiuthMiddleware({
  configLookup: (key) => key === apiKey ? configs.basic : null,
});

const ipAuth = createQiuthMiddleware({
  configLookup: (key) => key === apiKey ? configs.withIp : null,
});

const totpAuth = createQiuthMiddleware({
  configLookup: (key) => key === apiKey ? configs.withTotp : null,
});

const fullAuth = createQiuthMiddleware({
  configLookup: (key) => key === apiKey ? configs.full : null,
});

// Protected endpoints
app.get('/api/basic', basicAuth, (_req: Request, res: Response) => {
  res.json({
    message: '✅ Level 1: API Key authentication successful',
    security: ['API Key'],
    data: { timestamp: new Date().toISOString() },
  });
});

app.get('/api/with-ip', ipAuth, (req: Request, res: Response) => {
  res.json({
    message: '✅ Level 2: API Key + IP Allowlist authentication successful',
    security: ['API Key', 'IP Allowlist'],
    clientIp: req.ip,
    data: { timestamp: new Date().toISOString() },
  });
});

app.get('/api/with-totp', totpAuth, (_req: Request, res: Response) => {
  res.json({
    message: '✅ Level 3: API Key + IP + TOTP authentication successful',
    security: ['API Key', 'IP Allowlist', 'TOTP MFA'],
    data: { timestamp: new Date().toISOString() },
  });
});

app.get('/api/full', fullAuth, (_req: Request, res: Response) => {
  res.json({
    message: '✅ Level 4: Full multi-factor authentication successful!',
    security: ['API Key', 'IP Allowlist', 'TOTP MFA', 'Certificate Signature'],
    data: {
      timestamp: new Date().toISOString(),
      message: 'This is the most secure endpoint - all three layers verified!'
    },
  });
});

app.post('/api/data', fullAuth, (req: Request, res: Response) => {
  res.json({
    message: '✅ POST with full security successful',
    received: req.body,
    timestamp: new Date().toISOString(),
  });
});

// Start server
const PORT = process.env['PORT'] || 3000;
app.listen(PORT, () => {
  console.log('\n🚀 Demo server running on http://localhost:' + PORT);
  console.log('\n📖 Quick Start:');
  console.log('   1. Visit http://localhost:3000 for full instructions');
  console.log('   2. Copy the test commands and run them in your terminal');
  console.log('   3. See authentication in action!\n');
  console.log('💡 Important: TOTP tokens are 6-digit codes that change every 30 seconds');
  console.log('   Get current token: curl http://localhost:3000/totp/current');
  console.log('   Use the "token" field (e.g., "930883"), NOT the "secret" field!\n');
  console.log('='.repeat(80) + '\n');
});

