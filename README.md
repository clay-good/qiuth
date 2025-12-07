# Qiuth

**Multi-Factor Authentication for API Keys** - Stop treating API keys like passwords.

> **Qiuth** transforms API keys from bearer tokens into proof-of-possession tokens, requiring multiple authentication factors to prevent unauthorized access even if your API key is leaked.

Pronounced **chew-auth**. Inspired by [Kevin Qiu](https://www.linkedin.com/in/kevinmqiu)

---

## The Problem

**API keys are single points of failure.** If your API key is leaked (committed to GitHub, intercepted in transit, stolen from logs), an attacker has **unlimited access** to your API.

```bash
# Your .env file accidentally committed to GitHub
API_KEY=sk_live_abc123def456

# Attacker finds it and has full access
curl -H "Authorization: Bearer sk_live_abc123def456" https://api.yourapp.com/data
# SUCCESS - Attacker downloads all your data
```

**This happens more often than you think:**
- Thousands of API keys leaked on GitHub every day
- `.env` files accidentally committed to public repos
- API keys logged in error messages or monitoring tools
- Keys intercepted in transit or stolen from compromised systems
- Even with key pairs, if the private key is leaked, it's game over

---

## The Solution

**Qiuth adds multi-factor authentication to your API keys**, transforming them from bearer tokens (anyone with the key can use it) into **proof-of-possession tokens** (you need the key PLUS additional factors).

### Multiple Layers of Defense

1. **IP Allowlisting** - First line of defense
   - Verify requests come from authorized locations
   - Support for IPv4/IPv6 CIDR notation
   - Blocks unauthorized networks immediately

2. **TOTP MFA** - Time-based one-time passwords
   - Works for service accounts (programmatic)
   - Tokens change every 30 seconds
   - Even if API key is leaked, attacker needs TOTP secret

3. **Request Signing** - Cryptographic proof (choose one):

   **Certificate Authentication** (asymmetric)
   - Requires RSA private key to sign each request
   - Only public key stored on server
   - Best for external clients or when key distribution is a concern

   **HMAC Authentication** (symmetric)
   - Uses shared secret for request signing
   - Simpler setup, same security for internal services
   - Best for trusted environments and service-to-service communication

4. **Timestamp Validation** - Prevents replay attacks
   - Signed requests include timestamp
   - Server rejects stale requests (configurable window)
   - Even captured requests cannot be replayed

### Real-World Impact

**After Qiuth:**
```bash
# API key leaked in GitHub
API_KEY=sk_live_abc123def456

# Attacker tries to use it
curl -H "X-API-Key: sk_live_abc123def456" https://api.yourapp.com/data
# FAILED: 401 Unauthorized - IP not in allowlist

# Attacker would need ALL of these:
# 1. API key (leaked)
# 2. TOTP secret (stored separately)
# 3. Signing key (private key OR HMAC secret)
# = Virtually impossible to compromise
```

---

## Why Qiuth?

### The Non-Human Identity (NHI) Security Gap

We invest heavily in multi-factor authentication for human accounts. Password managers, authenticator apps, hardware keys - the security industry has made MFA standard for people.

**But what about service accounts?**

Service accounts, API clients, and machine-to-machine integrations typically authenticate with:
- Static API keys that never rotate
- OAuth client_id/client_secret pairs with no second factor
- Long-lived tokens with no additional verification

This creates a fundamental security gap: **non-human identities have weaker authentication than human identities**, despite often having broader access to sensitive systems.

### The OAuth Client Secret Problem

Many developers think "just use OAuth" solves API security. But OAuth client secrets have the same vulnerabilities as API keys:

- **Client secrets are static** - They don't change unless manually rotated
- **Client secrets are reusable** - Anyone with the secret can request tokens
- **Client secrets can be intercepted** - MITM the initial token request and you have the secret
- **Client secrets are essentially passwords** - With all the same risks of credential theft

The JP Morgan Chase CISO's [open letter to third-party suppliers](https://www.jpmorganchase.com/about/technology/blog/open-letter-to-our-suppliers) highlighted these exact concerns about OAuth and current authentication standards for machine-to-machine communication.

### Why IP Allowlisting Should Be Standard

A simple question: **Why is it so difficult for SaaS apps to add IP allowlisting?**

Consider this real-world scenario: An engineer accidentally commits a config file containing a root access key to a public repository. Within minutes, automated scanners find it. The key is compromised.

This could have been a non-issue with a simple IAM policy:
```
Deny all access with this key if source IP is not in [VPN_STATIC_IP]
```

Even trivial IP validation - reading the X-Forwarded-For header before returning a response - would dramatically reduce the blast radius of leaked credentials. Yet most APIs don't offer this basic protection.

Qiuth makes IP allowlisting a first-class feature, not an afterthought.

### Qiuth's Approach: MFA for ALL Identities

Qiuth applies the same security rigor to service accounts that we expect for human accounts:

| Human Account | Service Account (with Qiuth) |
|--------------|------------------------------|
| Password | API Key |
| IP-based access controls | IP Allowlisting (Layer 1) |
| Authenticator app (TOTP) | TOTP for services (Layer 2) |
| Hardware security key | Certificate signing (Layer 3) |

The result: even if your API key leaks, an attacker needs to also compromise your TOTP secret AND your private key AND make requests from an allowed IP address.

**That's defense in depth for machine identities.**

---

## Quick Start

### Installation

```bash
npm install qiuth
```

### Basic Usage

```typescript
import { QiuthConfigBuilder, QiuthAuthenticator, generateKeyPair } from 'qiuth';

// Generate certificate key pair for maximum security
const { publicKey, privateKey } = generateKeyPair({ modulusLength: 2048 });

// Configure all three security layers
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key')
  .withIpAllowlist(['192.168.1.0/24'])
  .withTotp('your-totp-secret')
  .withCertificate(publicKey) // Add certificate-based authentication
  .build();

// Authenticate requests
const authenticator = new QiuthAuthenticator();
const result = await authenticator.authenticate({
  apiKey: 'user-provided-key',
  clientIp: '192.168.1.100',
  totpToken: '123456',
  signature: 'base64-signature', // Required when using withCertificate
  timestamp: Date.now().toString(),
  method: 'GET',
  url: 'https://api.example.com/resource',
}, config);

if (result.success) {
  console.log('Authentication successful!');
} else {
  console.error('Authentication failed:', result.errors);
}
```

**Note:** Use `.withCertificate(publicKey)` for maximum security. This requires clients to cryptographically sign each request with their private key, providing proof-of-possession that prevents unauthorized access even if API keys and TOTP secrets are compromised.

### Framework Middleware

Qiuth provides middleware for popular Node.js frameworks:

| Framework | Function | Runtime |
|-----------|----------|---------|
| Express | `createQiuthMiddleware` | Node.js |
| Fastify | `qiuthFastifyPlugin` | Node.js |
| Koa | `createQiuthKoaMiddleware` | Node.js |
| Hono | `createQiuthHonoMiddleware` | Node.js, Cloudflare Workers, Deno, Bun |

#### Express

```typescript
import express from 'express';
import { createQiuthMiddleware, QiuthConfigBuilder } from 'qiuth';

const app = express();

const qiuthAuth = createQiuthMiddleware({
  configLookup: async (apiKey) => {
    return await db.getApiKeyConfig(apiKey);
  },
});

app.get('/api/protected', qiuthAuth, (req, res) => {
  res.json({ message: 'Access granted!' });
});
```

#### Fastify

```typescript
import fastify from 'fastify';
import { qiuthFastifyPlugin } from 'qiuth';

const app = fastify();

app.register(qiuthFastifyPlugin, {
  configLookup: async (apiKey) => await db.getApiKeyConfig(apiKey),
});

app.get('/protected', { preHandler: app.qiuthAuth }, async (request, reply) => {
  return { authenticated: true };
});
```

#### Koa

```typescript
import Koa from 'koa';
import { createQiuthKoaMiddleware } from 'qiuth';

const app = new Koa();

const qiuthMiddleware = createQiuthKoaMiddleware({
  configLookup: async (apiKey) => await db.getApiKeyConfig(apiKey),
});

app.use(qiuthMiddleware);
```

#### Hono (Edge-ready)

```typescript
import { Hono } from 'hono';
import { createQiuthHonoMiddleware } from 'qiuth';

const app = new Hono();

app.use('/api/*', createQiuthHonoMiddleware({
  configLookup: async (apiKey) => await db.getApiKeyConfig(apiKey),
}));
```

[Full Middleware Documentation](./docs/middleware-integrations.md)

---

## Interactive Demo

**See Qiuth in action in 5 minutes!**

```bash
# Clone the repo
git clone https://github.com/clay-good/qiuth.git
cd qiuth

# Install dependencies
npm install

# Start the interactive demo
npm run demo
```

The demo server will start and display test credentials. Open a new terminal and try the test commands to see all three security layers in action!

**What you'll experience:**
- Level 1: Basic API key authentication
- Level 2: API key + IP allowlisting
- Level 3: API key + IP + TOTP MFA
- Level 4: Full security (all three layers)
- Failure scenarios (wrong credentials, expired tokens, invalid signatures)

[**Full Demo Guide**](./demo/README.md)

---

## Features

### Security
- **Three-layer authentication** - IP, TOTP, and certificate-based
- **Fail-fast validation** - Stop at first failure for performance
- **Replay attack prevention** - Timestamp validation
- **Secure credential generation** - Cryptographically secure random generation
- **API key hashing** - SHA-256 for secure storage

### Developer Experience
- **TypeScript-first** - Full type definitions included
- **Fluent API** - Intuitive configuration builder
- **Express middleware** - Drop-in authentication
- **HTTP client** - Automatic request signing
- **CLI tool** - Generate credentials easily

### Production Ready
- **Zero-downtime credential rotation** - Transition periods for updates
- **Structured logging** - Comprehensive observability
- **Metrics collection** - Track authentication performance
- **Environment configuration** - Load from env vars
- **Comprehensive error handling** - Detailed error messages

### Build & Distribution
- **Dual module support** - ESM and CommonJS
- **Tree-shakeable** - Import only what you need
- **Zero dependencies** - Only Node.js built-ins
- **Well-tested** - 318 tests with 90%+ coverage

---

## Use Cases

### 1. Service-to-Service Authentication
Secure microservices communication with MFA:
```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(process.env.API_KEY)
  .withIpAllowlist(['10.0.0.0/8']) // Internal network
  .withTotp(process.env.TOTP_SECRET)
  .build();
```

### 2. API Key Management
Add MFA to your existing API key system:
```typescript
app.use('/api', createQiuthMiddleware({ config }));
```

### 3. Compliance Requirements
Meet PCI DSS, SOC 2, HIPAA security requirements:
```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withIpAllowlist(allowedIps)
  .withTotp(totpSecret)
  .withCertificate(publicKey) // Maximum security
  .build();
```

### 4. CI/CD Pipeline Security
Secure automated deployments:
```typescript
// GitHub Actions, Jenkins, etc.
const client = new QiuthClient({
  apiKey: process.env.API_KEY,
  totpSecret: process.env.TOTP_SECRET,
  privateKey: process.env.PRIVATE_KEY,
});
```

---

## Security

Qiuth is designed with security as the top priority:

- **No sensitive data logging** - API keys and secrets never logged
- **Cryptographically secure** - Uses Node.js crypto module
- **RFC compliant** - TOTP follows RFC 6238
- **Industry standards** - RSA-SHA256 signatures
- **Regular audits** - Automated security scanning

---

## Performance

Qiuth is designed for production use with minimal overhead:

- **IP Validation**: < 1ms
- **TOTP Validation**: < 5ms
- **Certificate Validation**: < 10ms
- **Total**: < 20ms for all three layers

**Bundle Size:**
- ESM: ~60 KB
- CommonJS: ~61 KB
- TypeScript declarations: ~48 KB

---

<div align="center">

**Stop treating API keys like passwords. Add multi-factor authentication today.**

[Get Started](./docs/getting-started.md) • [Try the Demo](./demo/README.md) • [Readme](https://github.com/clay-good/qiuth/readme.md)

</div>

