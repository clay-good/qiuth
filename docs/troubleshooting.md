# Troubleshooting Guide

This guide helps diagnose and resolve common issues when using Qiuth.

## Table of Contents

- [Authentication Failures](#authentication-failures)
  - [API Key Issues](#api-key-issues)
  - [IP Allowlist Issues](#ip-allowlist-issues)
  - [TOTP Issues](#totp-issues)
  - [Certificate/HMAC Signing Issues](#certificatehmac-signing-issues)
- [Middleware Issues](#middleware-issues)
- [Configuration Issues](#configuration-issues)
- [Performance Issues](#performance-issues)
- [Client Library Issues](#client-library-issues)

---

## Authentication Failures

### API Key Issues

#### Error: "API key is required"

**Cause:** The middleware cannot find the API key in the request.

**Solutions:**

1. Check the header name (default is `x-api-key`):
```bash
# Correct
curl -H "x-api-key: your-api-key" https://api.example.com/

# Wrong header name
curl -H "X-Api-Key: your-api-key" https://api.example.com/
# Note: Header names are case-insensitive in HTTP, but check your middleware config
```

2. If using query parameters, ensure `allowQueryKey` is enabled:
```typescript
const middleware = createQiuthMiddleware({
  allowQueryKey: true, // Must be true to use query param
  apiKeyQuery: 'api_key', // Default parameter name
});
```

3. Verify the header is not being stripped by a proxy or CDN.

#### Error: "Invalid API key"

**Cause:** The API key does not match any stored configuration.

**Solutions:**

1. Verify the key is correct (check for whitespace or encoding issues):
```typescript
const apiKey = process.env.API_KEY?.trim();
```

2. Check that the config lookup function returns the correct config:
```typescript
const middleware = createQiuthMiddleware({
  configLookup: async (apiKey) => {
    console.log('Looking up key:', apiKey); // Debug
    const config = await db.getConfig(apiKey);
    console.log('Found config:', !!config); // Debug
    return config;
  },
});
```

3. Ensure the stored hashed key was generated from the same API key:
```typescript
import { QiuthAuthenticator } from 'qiuth';

const hashedKey = QiuthAuthenticator.hashApiKey('your-api-key');
console.log('Expected hash:', hashedKey);
// Compare with stored hash
```

---

### IP Allowlist Issues

#### Error: "Client IP not in allowlist"

**Cause:** The client's IP address is not included in the allowed IP ranges.

**Solutions:**

1. Check the actual client IP being received:
```typescript
const middleware = createQiuthMiddleware({
  debug: true, // Enable debug logging
  logger: console.log,
});
```

2. If behind a proxy/load balancer, enable `trustProxy`:
```typescript
.withIpAllowlist(['192.168.1.0/24'], true) // trustProxy = true
```

3. Check common proxy headers in order of precedence:
   - `cf-connecting-ip` (Cloudflare)
   - `x-forwarded-for` (most proxies)
   - `x-real-ip` (nginx)

4. Verify your IP range notation:
```typescript
// Single IP
'192.168.1.100'

// CIDR notation
'192.168.1.0/24' // Covers 192.168.1.0 - 192.168.1.255

// IPv6
'2001:db8::/32'
```

5. Test IP matching directly:
```typescript
import { IpValidator } from 'qiuth';

const validator = new IpValidator({
  enabled: true,
  allowedIps: ['192.168.1.0/24'],
});

console.log(validator.isAllowed('192.168.1.100')); // true or false
```

#### Debugging IP Issues

```typescript
// Log the extracted IP at middleware level
app.use((req, res, next) => {
  console.log('Socket IP:', req.socket.remoteAddress);
  console.log('X-Forwarded-For:', req.headers['x-forwarded-for']);
  console.log('CF-Connecting-IP:', req.headers['cf-connecting-ip']);
  console.log('Express req.ip:', req.ip);
  next();
});
```

---

### TOTP Issues

#### Error: "Invalid TOTP token" or "TOTP token is required"

**Cause:** The TOTP token is missing, expired, or incorrect.

**Solutions:**

1. Check time synchronization between client and server:
```typescript
import { TotpValidator } from 'qiuth';

const validator = new TotpValidator({
  enabled: true,
  secret: 'your-totp-secret',
});

// Check remaining time in current window
console.log('Remaining time:', validator.getRemainingTime(), 'seconds');

// Generate current valid token (for debugging)
console.log('Current token:', validator.generate());
```

2. Increase the drift window for network latency:
```typescript
.withTotp(secret, 30, 2) // Allow +/- 2 time steps (90 second window)
```

3. Verify the secret is correct:
   - Secrets must be Base32 encoded
   - Common characters: A-Z, 2-7
   - No lowercase, no 0, 1, 8, 9

4. Check for token reuse (if your implementation prevents replay):
```typescript
// Tokens should only be accepted once
// If you're seeing intermittent failures, check for duplicate requests
```

#### Token Format Issues

```bash
# Correct: 6 digits, zero-padded
"012345"
"123456"

# Wrong: not zero-padded
"12345"  # Missing leading zero

# Wrong: non-numeric
"12345a"
```

---

### Certificate/HMAC Signing Issues

#### Error: "Invalid signature" or "Signature verification failed"

**Cause:** The signature doesn't match the expected value.

**Solutions:**

1. Verify all signed components match exactly:
```typescript
// Client side - what you're signing
const signature = CertificateValidator.sign(
  privateKey,
  'POST',           // Must match exactly (case-insensitive normalized)
  'https://api.example.com/users', // Must match exactly
  '{"name":"John"}', // Must match exactly, including whitespace
  1699900000000     // Timestamp must match
);

// Server side - what the server sees
// Any difference in method, URL, body, or timestamp = invalid signature
```

2. Check for URL encoding/normalization issues:
```typescript
// These are different URLs for signature purposes:
'https://api.example.com/users?a=1&b=2'
'https://api.example.com/users?b=2&a=1' // Different order

// URL fragments are stripped:
'https://api.example.com/users#section' -> 'https://api.example.com/users'
```

3. Check body serialization:
```typescript
// Wrong: Objects are serialized differently
const body1 = JSON.stringify({ a: 1, b: 2 });
const body2 = JSON.stringify({ b: 2, a: 1 }); // Different order = different signature

// Solution: Use consistent serialization
const body = JSON.stringify(data, Object.keys(data).sort());
```

4. For HMAC, verify the secret matches:
```typescript
// Client and server must use identical secrets
const secret = 'your-32-character-or-longer-secret';

// Check secret length
console.log('Secret length:', secret.length); // Must be >= 32
```

#### Error: "Request timestamp too old" or "Request expired"

**Cause:** The timestamp in the signed request is outside the acceptable window.

**Solutions:**

1. Check clock synchronization:
```typescript
console.log('Server time:', Date.now());
console.log('Request timestamp:', request.timestamp);
console.log('Difference:', Date.now() - request.timestamp, 'ms');
```

2. Increase the maxAge if needed:
```typescript
.withHmac(secret, 600) // 10 minutes instead of default 5
.withCertificate(publicKey, 600)
```

3. Verify timestamp format:
```typescript
// Correct: Unix timestamp in milliseconds
const timestamp = Date.now(); // 1699900000000

// Wrong: Unix timestamp in seconds
const timestamp = Math.floor(Date.now() / 1000); // 1699900000

// Also accepted: ISO 8601 string
const timestamp = new Date().toISOString();
```

#### Error: "Future timestamp rejected"

**Cause:** The request timestamp is in the future (beyond tolerance).

**Solutions:**

1. Check for clock drift on the client machine
2. Default tolerance is 60 seconds into the future
3. Ensure client uses current time, not cached values

---

## Middleware Issues

### Express Middleware Not Working

**Symptom:** Middleware doesn't seem to authenticate requests.

**Solutions:**

1. Check middleware order:
```typescript
// Body parser must come BEFORE Qiuth middleware for signature verification
app.use(express.json());
app.use(express.raw({ type: '*/*' })); // For binary bodies
app.use('/api', qiuthMiddleware);
```

2. Ensure middleware is actually being applied:
```typescript
const qiuthMiddleware = createQiuthMiddleware({
  debug: true,
  logger: console.log, // Should see logs on every request
});
```

3. Check for errors in configLookup:
```typescript
configLookup: async (apiKey) => {
  try {
    return await db.getConfig(apiKey);
  } catch (error) {
    console.error('Config lookup error:', error);
    return null; // Return null on error, don't throw
  }
}
```

### Fastify Plugin Issues

**Symptom:** Plugin registration fails or decorator not found.

**Solutions:**

1. Ensure proper plugin registration:
```typescript
import { qiuthFastifyPlugin } from 'qiuth';

// Register with await
await app.register(qiuthFastifyPlugin, {
  configLookup: async (apiKey) => { /* ... */ }
});

// Or in a plugin context
app.register(qiuthFastifyPlugin, options);
```

2. Access the decorator correctly:
```typescript
// After registration, access via request
app.get('/protected', {
  preHandler: app.qiuthAuth,
}, async (request) => {
  const auth = request.qiuth; // Access auth info
});
```

### Hono Middleware Issues

**Symptom:** Context variables not available.

**Solutions:**

1. Define types properly:
```typescript
import { Hono } from 'hono';
import { QiuthHonoVariables } from 'qiuth';

const app = new Hono<{ Variables: QiuthHonoVariables }>();
```

2. Access context correctly:
```typescript
app.get('/protected', qiuthMiddleware, (c) => {
  const auth = c.get('qiuth');
  return c.json({ apiKey: auth?.apiKey });
});
```

---

## Configuration Issues

### Error: "API key is required. Use withApiKey() or withHashedApiKey()"

**Cause:** Building config without setting an API key.

**Solution:**
```typescript
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key') // Must call this
  .build();
```

### Error: "allowedIps must contain at least one IP address"

**Cause:** Enabling IP allowlist without specifying any IPs.

**Solution:**
```typescript
.withIpAllowlist(['192.168.1.0/24']) // Must have at least one IP

// Or disable it explicitly
.withoutIpAllowlist()
```

### Error: "HMAC secret must be at least 32 characters"

**Cause:** HMAC secret is too short.

**Solution:**
```typescript
import { HmacValidator } from 'qiuth';

// Generate a proper secret
const secret = HmacValidator.generateSecret(); // 64 hex chars (32 bytes)

// Or use your own (minimum 32 characters)
const secret = 'your-secret-that-is-at-least-32-characters-long';
```

---

## Performance Issues

### Slow Authentication

**Symptoms:** High latency on authenticated requests.

**Solutions:**

1. Cache configuration lookups:
```typescript
const configCache = new Map();

const middleware = createQiuthMiddleware({
  configLookup: async (apiKey) => {
    if (configCache.has(apiKey)) {
      return configCache.get(apiKey);
    }
    const config = await db.getConfig(apiKey);
    if (config) {
      configCache.set(apiKey, config);
      // Set expiry
      setTimeout(() => configCache.delete(apiKey), 60000);
    }
    return config;
  },
});
```

2. Use connection pooling for database lookups

3. Consider caching at the application level, not per-request

### High Memory Usage

**Symptoms:** Memory growing over time.

**Solutions:**

1. Check for memory leaks in configLookup closures
2. Limit cache size if using in-memory caching
3. Ensure metrics collection doesn't accumulate indefinitely

---

## Client Library Issues

### QiuthClient Request Failures

**Symptom:** All requests fail with authentication errors.

**Solutions:**

1. Verify all credentials are set correctly:
```typescript
const client = new QiuthClient({
  apiKey: process.env.API_KEY,        // Required
  baseUrl: 'https://api.example.com', // No trailing slash
  totpSecret: process.env.TOTP_SECRET, // If TOTP is enabled
  hmacSecret: process.env.HMAC_SECRET, // If HMAC is enabled
  // OR
  privateKey: process.env.PRIVATE_KEY, // If certificate auth is enabled
});
```

2. Check for environment variable issues:
```typescript
console.log('API Key set:', !!process.env.API_KEY);
console.log('TOTP Secret set:', !!process.env.TOTP_SECRET);
```

3. Verify baseUrl format:
```typescript
// Correct
baseUrl: 'https://api.example.com'

// Wrong - trailing slash causes issues
baseUrl: 'https://api.example.com/'

// Wrong - missing protocol
baseUrl: 'api.example.com'
```

### Request Timeout

**Symptom:** Requests timing out.

**Solutions:**

1. Increase timeout:
```typescript
const client = new QiuthClient({
  timeout: 60000, // 60 seconds
});
```

2. Check network connectivity to the API server

3. Verify the server is running and accessible

---

## Debug Mode

Enable debug mode for detailed logging:

```typescript
// Middleware
const middleware = createQiuthMiddleware({
  debug: true,
  logger: (message) => console.log('[Qiuth]', message),
});

// Authenticator
const authenticator = new QiuthAuthenticator({
  debug: true,
  logger: console.log,
});
```

**Debug output includes:**
- Configuration being used
- Layer-by-layer validation results
- Timing information
- Error details

---

## Getting Help

If you're still experiencing issues:

1. Check the [GitHub Issues](https://github.com/anthropics/qiuth/issues) for similar problems
2. Review the [API Reference](./api-reference.md) for correct usage
3. Enable debug mode and review the output
4. Create a minimal reproduction case
5. Open a new issue with:
   - Qiuth version
   - Node.js version
   - Minimal code to reproduce
   - Expected vs actual behavior
   - Debug output (with secrets redacted)
