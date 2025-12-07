# Getting Started with Qiuth

Qiuth (pronounced "chew-auth") is a TypeScript SDK that transforms API keys from simple bearer tokens into multi-factor authenticated credentials. This guide will help you get started quickly.

## Installation

```bash
npm install qiuth
# or
yarn add qiuth
# or
pnpm add qiuth
```

## Quick Start

### 1. Basic API Key Authentication

The simplest use case - just validate API keys:

```typescript
import { QiuthAuthenticator, QiuthConfigBuilder } from 'qiuth';

// Create configuration
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .build();

// Create authenticator
const authenticator = new QiuthAuthenticator();

// Authenticate a request
const result = await authenticator.authenticate({
  apiKey: 'user-provided-api-key',
  clientIp: '192.168.1.100',
  method: 'GET',
  url: 'https://api.example.com/resource',
}, config);

if (result.success) {
  console.log('Authentication successful!');
} else {
  console.error('Authentication failed:', result.errors);
}
```

### 2. Add IP Allowlisting

Restrict API key usage to specific IP addresses or ranges:

```typescript
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .withIpAllowlist([
    '192.168.1.0/24',  // CIDR notation
    '10.0.0.1',        // Single IP
    '2001:db8::/32',   // IPv6 support
  ])
  .build();
```

### 3. Add TOTP-based MFA

Require time-based one-time passwords for service accounts:

```typescript
import { generateTotpSecret } from 'qiuth';

// Generate a secret (do this once, store securely)
const totpSecret = generateTotpSecret();
console.log('TOTP Secret:', totpSecret);

// Configure with TOTP
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .withTotp(totpSecret, 30, 1) // timeStep=30s, window=1
  .build();

// Client must provide TOTP token
const result = await authenticator.authenticate({
  apiKey: 'user-provided-api-key',
  clientIp: '192.168.1.100',
  totpToken: '123456', // 6-digit TOTP code
  method: 'GET',
  url: 'https://api.example.com/resource',
}, config);
```

### 4. Add Certificate-based Authentication (Recommended for Maximum Security)

**Use `.withCertificate()` for the highest level of security.** This requires cryptographic proof of private key possession, preventing unauthorized access even if API keys and TOTP secrets are compromised.

```typescript
import { generateKeyPair, CertificateValidator } from 'qiuth';

// Generate key pair (do this once, store private key securely)
const { publicKey, privateKey } = generateKeyPair({ modulusLength: 2048 });

// Server configuration - store publicKey in your config
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .withIpAllowlist(['192.168.1.0/24'])
  .withTotp(totpSecret)
  .withCertificate(publicKey, 300) // maxAge=300 seconds
  .build();

// Client must sign each request
const timestamp = Date.now();
const signature = CertificateValidator.sign(
  privateKey,
  'GET',
  'https://api.example.com/resource',
  '', // request body (empty for GET)
  timestamp
);

// Authenticate with signature
const result = await authenticator.authenticate({
  apiKey: 'user-provided-api-key',
  clientIp: '192.168.1.100',
  totpToken: '123456',
  method: 'GET',
  url: 'https://api.example.com/resource',
  timestamp: timestamp.toString(),
  signature,
}, config);
```

**Key Benefits:**
- Prevents replay attacks with timestamp validation
- Even if API key and TOTP are leaked, attacker needs the private key
- Private key never leaves the client's secure environment
- Cryptographically verifiable proof-of-possession

### 5. Add HMAC-based Authentication (Lightweight Alternative)

**Use `.withHmac()` when you need request signing without the overhead of RSA certificates.** HMAC uses a shared secret for symmetric signing - simpler to set up but requires both client and server to securely store the secret.

```typescript
import { HmacValidator } from 'qiuth';

// Generate shared secret (do this once, distribute securely)
const hmacSecret = HmacValidator.generateSecret(); // 64 hex chars (256 bits)

// Server configuration
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .withIpAllowlist(['192.168.1.0/24'])
  .withHmac(hmacSecret, 300) // maxAge=300 seconds
  .build();

// Client must sign each request
const timestamp = Date.now();
const hmacSignature = HmacValidator.sign(
  hmacSecret,
  'POST',
  'https://api.example.com/resource',
  JSON.stringify({ data: 'example' }),
  timestamp
);

// Authenticate with HMAC signature
const result = await authenticator.authenticate({
  apiKey: 'user-provided-api-key',
  clientIp: '192.168.1.100',
  method: 'POST',
  url: 'https://api.example.com/resource',
  body: JSON.stringify({ data: 'example' }),
  timestamp: timestamp.toString(),
  hmacSignature,
}, config);
```

**When to use HMAC vs Certificates:**

| Feature | HMAC | Certificates |
|---------|------|--------------|
| Key type | Symmetric (shared secret) | Asymmetric (public/private) |
| Setup complexity | Simple | More complex |
| Key distribution | Must share secret securely | Only share public key |
| Non-repudiation | No | Yes |
| Best for | Internal services, trusted environments | External clients, untrusted networks |

## Express Middleware

Qiuth provides Express middleware for easy integration:

```typescript
import express from 'express';
import { createQiuthMiddleware } from 'qiuth';

const app = express();

// Create middleware
const qiuthAuth = createQiuthMiddleware({
  config: new QiuthConfigBuilder()
    .withApiKey('your-api-key-here')
    .withIpAllowlist(['0.0.0.0/0'])
    .build(),
  onSuccess: (req, res, result) => {
    console.log('Auth successful:', result);
  },
  onFailure: (req, res, result) => {
    console.error('Auth failed:', result.errors);
  },
});

// Apply to routes
app.get('/api/protected', qiuthAuth, (req, res) => {
  res.json({ message: 'Access granted!' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## Client Library

Use the QiuthClient for making authenticated requests:

```typescript
import { QiuthClient } from 'qiuth';

const client = new QiuthClient({
  baseUrl: 'https://api.example.com',
  apiKey: 'your-api-key',
  totpSecret: 'your-totp-secret', // optional
  hmacSecret: 'your-hmac-secret', // optional - use this OR privateKey
  privateKey: 'your-private-key', // optional - use this OR hmacSecret
});

// Make authenticated requests
const response = await client.get('/resource');
console.log(response);

// POST with body
const created = await client.post('/resource', {
  name: 'New Resource',
  value: 42,
});
```

## CLI Tool

Generate credentials using the CLI:

```bash
# Generate API key
npx qiuth generate api-key

# Generate TOTP secret
npx qiuth generate totp

# Generate HMAC shared secret
npx qiuth generate hmac-secret

# Generate RSA key pair
npx qiuth generate keypair --modulus 2048

# Generate all credentials at once
npx qiuth generate all
```

## Environment Variables

Load configuration from environment variables:

```typescript
import { loadConfigFromEnv } from 'qiuth';

// Set environment variables:
// QIUTH_API_KEY=your-api-key
// QIUTH_IP_ALLOWLIST=192.168.1.0/24,10.0.0.1
// QIUTH_TOTP_SECRET=BASE32SECRET
// QIUTH_CERTIFICATE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----...

const config = loadConfigFromEnv();
const authenticator = new QiuthAuthenticator();
```

## Next Steps

- Read the [Configuration Guide](./configuration.md) for detailed configuration options
- Learn about [Security Best Practices](./security-best-practices.md)
- Explore [Example Applications](../examples/)
- Check out the [API Reference](./api-reference.md)
- Review [Troubleshooting](./troubleshooting.md) for common issues

## Common Patterns

### All Layers for Maximum Security

For maximum security, combine multiple authentication layers:

```typescript
// Option 1: With Certificate signing (asymmetric)
const configWithCert = new QiuthConfigBuilder()
  .withApiKey('your-api-key')
  .withIpAllowlist(['192.168.1.0/24'])
  .withTotp(totpSecret)
  .withCertificate(publicKey)
  .build();

// Option 2: With HMAC signing (symmetric, simpler)
const configWithHmac = new QiuthConfigBuilder()
  .withApiKey('your-api-key')
  .withIpAllowlist(['192.168.1.0/24'])
  .withTotp(totpSecret)
  .withHmac(hmacSecret)
  .build();
```

### Credential Rotation

Rotate credentials with zero downtime:

```typescript
import { CredentialRotator } from 'qiuth';

const rotator = new CredentialRotator(oldConfig, {
  transitionPeriod: 3600000, // 1 hour
  autoComplete: true,
});

// Start rotation
rotator.startRotation(newConfig);

// Both old and new credentials work during transition
// After transition period, only new credentials work
```

### Observability

Track authentication metrics and logs:

```typescript
import { MetricsCollector, Logger, LogLevel } from 'qiuth';

const metrics = new MetricsCollector();
const logger = new Logger({ level: LogLevel.INFO });

// Record authentication events
metrics.recordAuthentication({
  success: result.success,
  layers: [SecurityLayer.IP_ALLOWLIST, SecurityLayer.TOTP_MFA],
  duration: 15,
  timestamp: new Date(),
});

// Get summary
const summary = metrics.getSummary();
console.log(`Success rate: ${summary.successRate * 100}%`);
```

## Integration Examples

### OAuth2 Flow Integration

Wrap tokens returned by external identity providers (like Google, GitHub, Auth0) with Qiuth for added security:

```typescript
import express from 'express';
import { QiuthConfigBuilder, QiuthAuthenticator, generateApiKey, generateTotpSecret } from 'qiuth';

const app = express();
app.use(express.json());

// OAuth2 callback endpoint
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;

  // Exchange code for token with your OAuth2 provider
  const oauthToken = await exchangeCodeForToken(code);

  // Generate Qiuth credentials for this user
  const apiKey = generateApiKey();
  const totpSecret = generateTotpSecret();

  // Store in your database associated with the OAuth user
  await db.users.create({
    oauthId: oauthToken.userId,
    oauthProvider: 'google',
    qiuthApiKey: apiKey,
    qiuthTotpSecret: totpSecret,
    oauthAccessToken: oauthToken.access_token,
    oauthRefreshToken: oauthToken.refresh_token,
  });

  // Return credentials to client
  res.json({
    message: 'Authentication successful',
    credentials: {
      apiKey,
      totpSecret,
      // Client should generate their own key pair for certificate auth
      setupInstructions: 'Use these credentials with Qiuth for API access',
    },
  });
});

// Protected API endpoint using Qiuth
const qiuthAuth = createQiuthMiddleware({
  configLookup: async (apiKey) => {
    // Look up user by Qiuth API key
    const user = await db.users.findOne({ qiuthApiKey: apiKey });
    if (!user) return null;

    // Verify OAuth token is still valid
    const isValidOAuth = await verifyOAuthToken(user.oauthAccessToken);
    if (!isValidOAuth) {
      // Attempt refresh
      const refreshed = await refreshOAuthToken(user.oauthRefreshToken);
      if (!refreshed) return null;
      await db.users.update(user.id, { oauthAccessToken: refreshed.access_token });
    }

    // Return Qiuth config
    return new QiuthConfigBuilder()
      .withApiKey(user.qiuthApiKey)
      .withTotp(user.qiuthTotpSecret)
      .build();
  },
});

app.get('/api/user/profile', qiuthAuth, async (req, res) => {
  // Both OAuth2 and Qiuth auth passed
  const user = await db.users.findOne({ qiuthApiKey: req.qiuth.apiKey });
  res.json({ profile: user.profile });
});

async function exchangeCodeForToken(code: string) {
  // Implement OAuth2 code exchange with your provider
  const response = await fetch('https://oauth.provider.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      grant_type: 'authorization_code',
    }),
  });
  return response.json();
}

async function verifyOAuthToken(token: string): Promise<boolean> {
  // Verify token with OAuth provider
  try {
    const response = await fetch('https://oauth.provider.com/tokeninfo', {
      headers: { Authorization: `Bearer ${token}` },
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function refreshOAuthToken(refreshToken: string) {
  // Refresh OAuth token
  const response = await fetch('https://oauth.provider.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      refresh_token: refreshToken,
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      grant_type: 'refresh_token',
    }),
  });
  return response.ok ? response.json() : null;
}
```

### Express Session Integration

Integrate Qiuth with Express session middleware for web applications:

```typescript
import express from 'express';
import session from 'express-session';
import { QiuthConfigBuilder, generateApiKey, generateTotpSecret, TotpValidator } from 'qiuth';

const app = express();
app.use(express.json());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));

// Extend session type
declare module 'express-session' {
  interface SessionData {
    userId: string;
    qiuthApiKey: string;
    qiuthTotpSecret: string;
    authenticated: boolean;
  }
}

// Login endpoint - creates session with Qiuth credentials
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Verify username/password
  const user = await db.users.findOne({ username });
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate or retrieve Qiuth credentials for this user
  let apiKey = user.qiuthApiKey;
  let totpSecret = user.qiuthTotpSecret;

  if (!apiKey || !totpSecret) {
    apiKey = generateApiKey();
    totpSecret = generateTotpSecret();
    await db.users.update(user.id, { qiuthApiKey: apiKey, qiuthTotpSecret: totpSecret });
  }

  // Store in session
  req.session.userId = user.id;
  req.session.qiuthApiKey = apiKey;
  req.session.qiuthTotpSecret = totpSecret;
  req.session.authenticated = true;

  res.json({
    message: 'Login successful',
    credentials: {
      apiKey,
      totpSecret,
    },
  });
});

// Middleware to verify session + Qiuth auth for API calls
const sessionQiuthAuth = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  // First check session
  if (!req.session.authenticated || !req.session.qiuthApiKey) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Extract Qiuth credentials from request
  const apiKey = req.headers['x-api-key'] as string;
  const totpToken = req.headers['x-totp-token'] as string;

  // Verify API key matches session
  if (apiKey !== req.session.qiuthApiKey) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  // Build Qiuth config from session
  const config = new QiuthConfigBuilder()
    .withApiKey(req.session.qiuthApiKey)
    .withTotp(req.session.qiuthTotpSecret)
    .build();

  // Authenticate with Qiuth
  const authenticator = new QiuthAuthenticator();
  const result = await authenticator.authenticate({
    apiKey,
    clientIp: req.ip || req.socket.remoteAddress || '0.0.0.0',
    totpToken,
    method: req.method,
    url: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
  }, config);

  if (!result.success) {
    return res.status(401).json({
      error: 'Authentication failed',
      details: result.errors,
    });
  }

  next();
};

// Protected API routes
app.get('/api/data', sessionQiuthAuth, async (req, res) => {
  const user = await db.users.findOne({ id: req.session.userId });
  res.json({
    message: 'Access granted',
    data: user.data,
  });
});

app.post('/api/data', sessionQiuthAuth, async (req, res) => {
  const user = await db.users.findOne({ id: req.session.userId });
  await db.users.update(user.id, { data: req.body });
  res.json({ message: 'Data updated' });
});

// Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to logout' });
    }
    res.json({ message: 'Logged out successfully' });
  });
});

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  // Implement password verification (e.g., using bcrypt)
  const bcrypt = require('bcrypt');
  return bcrypt.compare(password, hash);
}
```

**Session Integration Benefits:**
- Combines traditional session-based auth with Qiuth MFA
- Session provides user context, Qiuth provides multi-factor security
- API keys and TOTP secrets are session-scoped
- Works seamlessly with existing Express session workflows
