# Qiuth API Reference

Complete API documentation for Qiuth v0.1.0.

## Table of Contents

- [Core Classes](#core-classes)
  - [QiuthAuthenticator](#qiuthauthenticator)
  - [QiuthConfigBuilder](#qiuthconfigbuilder)
  - [QiuthClient](#qiuthclient)
- [Validators](#validators)
  - [IpValidator](#ipvalidator)
  - [TotpValidator](#totpvalidator)
  - [CertificateValidator](#certificatevalidator)
  - [HmacValidator](#hmacvalidator)
- [Middleware](#middleware)
  - [createQiuthMiddleware](#createqiuthmiddleware)
- [Credential Management](#credential-management)
  - [CredentialRotator](#credentialrotator)
- [Observability](#observability)
  - [Logger](#logger)
  - [MetricsCollector](#metricscollector)
- [Utilities](#utilities)
  - [Crypto Functions](#crypto-functions)
  - [Config Loader](#config-loader)
- [Types & Interfaces](#types--interfaces)

---

## Core Classes

### QiuthAuthenticator

Core authenticator that orchestrates all security layers.

#### Constructor

```typescript
constructor(options?: AuthenticatorOptions)
```

**Parameters:**
- `options` (optional): Authenticator configuration
  - `debug?: boolean` - Enable debug logging (default: `false`)
  - `logger?: (message: string) => void` - Custom logger function
  - `collectMetrics?: boolean` - Enable metrics collection (default: `true`)

**Example:**
```typescript
const authenticator = new QiuthAuthenticator({
  debug: true,
  logger: console.log,
  collectMetrics: true,
});
```

#### Methods

##### `authenticate(request, config)`

Authenticate a request against a configuration.

```typescript
async authenticate(
  request: AuthenticationRequest,
  config: QiuthConfig
): Promise<ValidationResult>
```

**Parameters:**
- `request: AuthenticationRequest` - Request to authenticate
  - `apiKey: string` - API key provided by client
  - `clientIp: string` - Client IP address
  - `totpToken?: string` - TOTP token (if TOTP enabled)
  - `signature?: string` - Request signature (if certificate auth enabled)
  - `hmacSignature?: string` - HMAC signature (if HMAC auth enabled)
  - `timestamp?: string` - Request timestamp (for signature verification)
  - `method: string` - HTTP method (GET, POST, etc.)
  - `url: string` - Request URL
  - `body?: string` - Request body (for signature verification)
  - `headers?: Record<string, string | string[] | undefined>` - Request headers

- `config: QiuthConfig` - Configuration to validate against
  - `hashedApiKey: string` - SHA-256 hashed API key
  - `ipAllowlist?: IpAllowlistConfig` - IP allowlist configuration
  - `totp?: TotpConfig` - TOTP configuration
  - `certificate?: CertificateConfig` - Certificate configuration
  - `hmac?: HmacConfig` - HMAC configuration

**Returns:** `Promise<ValidationResult>`
- `success: boolean` - Whether authentication succeeded
- `layers: LayerValidationResult[]` - Results for each security layer
- `errors: string[]` - Array of error messages (if failed)
- `correlationId: string` - Unique ID for this authentication attempt
- `timestamp: number` - When authentication occurred
- `duration: number` - How long authentication took (ms)

**Example:**
```typescript
const result = await authenticator.authenticate({
  apiKey: 'user-provided-key',
  clientIp: '192.168.1.100',
  totpToken: '123456',
  method: 'GET',
  url: 'https://api.example.com/resource',
}, config);

if (result.success) {
  console.log('Authenticated!');
} else {
  console.error('Failed:', result.errors);
}
```

##### `hashApiKey(apiKey)` (static)

Hash an API key using SHA-256.

```typescript
static hashApiKey(apiKey: string): string
```

**Parameters:**
- `apiKey: string` - Plain text API key

**Returns:** `string` - SHA-256 hash (hex encoded)

**Example:**
```typescript
const hashed = QiuthAuthenticator.hashApiKey('my-api-key');
// Returns: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
```

---

### QiuthConfigBuilder

Fluent API for building Qiuth configurations.

#### Constructor

```typescript
constructor()
```

Creates a new configuration builder.

**Example:**
```typescript
const builder = new QiuthConfigBuilder();
```

#### Methods

##### `withApiKey(apiKey)`

Set the API key (will be hashed automatically).

```typescript
withApiKey(apiKey: string): this
```

**Parameters:**
- `apiKey: string` - Plain text API key

**Returns:** `this` (for chaining)

**Example:**
```typescript
builder.withApiKey('my-secret-key');
```

##### `withHashedApiKey(hashedApiKey)`

Set the hashed API key directly.

```typescript
withHashedApiKey(hashedApiKey: string): this
```

**Parameters:**
- `hashedApiKey: string` - Pre-hashed API key (SHA-256 hex)

**Returns:** `this` (for chaining)

##### `withIpAllowlist(allowedIps, trustProxy?)`

Enable IP allowlisting.

```typescript
withIpAllowlist(
  allowedIps: string[],
  trustProxy?: boolean
): this
```

**Parameters:**
- `allowedIps: string[]` - Array of IP addresses and CIDR ranges
  - Examples: `"192.168.1.100"`, `"192.168.1.0/24"`, `"2001:db8::/32"`
- `trustProxy?: boolean` - Trust X-Forwarded-For headers (default: `false`)

**Returns:** `this` (for chaining)

**Example:**
```typescript
builder.withIpAllowlist([
  '192.168.1.0/24',
  '10.0.0.1',
  '2001:db8::/32'
], true);
```

##### `withTotp(secret, timeStep?, window?)`

Enable TOTP MFA.

```typescript
withTotp(
  secret: string,
  timeStep?: number,
  window?: number
): this
```

**Parameters:**
- `secret: string` - Base32-encoded TOTP secret
- `timeStep?: number` - Time step in seconds (default: `30`)
- `window?: number` - Number of windows to accept (default: `1`)

**Returns:** `this` (for chaining)

**Example:**
```typescript
builder.withTotp('JBSWY3DPEHPK3PXP', 30, 1);
```

##### `withCertificate(publicKey, maxAge?)`

Enable certificate-based authentication.

```typescript
withCertificate(
  publicKey: string,
  maxAge?: number
): this
```

**Parameters:**
- `publicKey: string` - PEM-encoded RSA public key
- `maxAge?: number` - Maximum age of signatures in seconds (default: `300`)

**Returns:** `this` (for chaining)

**Example:**
```typescript
builder.withCertificate(
  '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  300
);
```

##### `withoutIpAllowlist()`

Disable IP allowlisting.

```typescript
withoutIpAllowlist(): this
```

##### `withoutTotp()`

Disable TOTP MFA.

```typescript
withoutTotp(): this
```

##### `withoutCertificate()`

Disable certificate authentication.

```typescript
withoutCertificate(): this
```

##### `withHmac(secret, maxAge?)`

Enable HMAC-based authentication.

```typescript
withHmac(
  secret: string,
  maxAge?: number
): this
```

**Parameters:**
- `secret: string` - Shared secret (minimum 32 characters)
- `maxAge?: number` - Maximum age of signatures in seconds (default: `300`)

**Returns:** `this` (for chaining)

**Example:**
```typescript
builder.withHmac(
  'your-32-character-or-longer-secret-here',
  300
);
```

##### `withoutHmac()`

Disable HMAC authentication.

```typescript
withoutHmac(): this
```

##### `build()`

Build the configuration.

```typescript
build(): QiuthConfig
```

**Returns:** `QiuthConfig` - Complete configuration object

**Throws:** `Error` if API key is not set

**Example:**
```typescript
const config = new QiuthConfigBuilder()
  .withApiKey('my-api-key')
  .withIpAllowlist(['192.168.1.0/24'])
  .withTotp('JBSWY3DPEHPK3PXP')
  .build();
```

---

### QiuthClient

HTTP client with automatic authentication.

#### Constructor

```typescript
constructor(options: QiuthClientOptions)
```

**Parameters:**
- `options: QiuthClientOptions`
  - `apiKey: string` - API key for authentication
  - `baseUrl: string` - Base URL for API requests
  - `totpSecret?: string` - TOTP secret (if TOTP enabled)
  - `hmacSecret?: string` - Shared secret for HMAC signing (if HMAC auth enabled)
  - `privateKey?: string` - PEM-encoded private key (if certificate auth enabled)
  - `timeout?: number` - Request timeout in ms (default: `30000`)
  - `retries?: number` - Number of retries (default: `3`)
  - `retryDelay?: number` - Delay between retries in ms (default: `1000`)
  - `headers?: Record<string, string>` - Additional headers

**Example:**
```typescript
// With certificate auth
const clientWithCert = new QiuthClient({
  apiKey: 'my-api-key',
  baseUrl: 'https://api.example.com',
  totpSecret: 'JBSWY3DPEHPK3PXP',
  privateKey: '-----BEGIN PRIVATE KEY-----\n...',
  timeout: 30000,
  retries: 3,
});

// With HMAC auth (simpler alternative)
const clientWithHmac = new QiuthClient({
  apiKey: 'my-api-key',
  baseUrl: 'https://api.example.com',
  totpSecret: 'JBSWY3DPEHPK3PXP',
  hmacSecret: 'your-32-character-or-longer-secret',
  timeout: 30000,
  retries: 3,
});
```

#### Methods

##### `get(path, options?)`

Make a GET request.

```typescript
async get<T = any>(
  path: string,
  options?: RequestOptions
): Promise<QiuthResponse<T>>
```

**Parameters:**
- `path: string` - Request path (relative to baseUrl)
- `options?: RequestOptions` - Additional request options
  - `headers?: Record<string, string>` - Additional headers
  - `timeout?: number` - Override default timeout

**Returns:** `Promise<QiuthResponse<T>>`
- `data: T` - Response data
- `status: number` - HTTP status code
- `headers: Record<string, string>` - Response headers

**Example:**
```typescript
const response = await client.get('/users');
console.log(response.data);
```

##### `post(path, body?, options?)`

Make a POST request.

```typescript
async post<T = any>(
  path: string,
  body?: any,
  options?: RequestOptions
): Promise<QiuthResponse<T>>
```

##### `put(path, body?, options?)`

Make a PUT request.

```typescript
async put<T = any>(
  path: string,
  body?: any,
  options?: RequestOptions
): Promise<QiuthResponse<T>>
```

##### `delete(path, options?)`

Make a DELETE request.

```typescript
async delete<T = any>(
  path: string,
  options?: RequestOptions
): Promise<QiuthResponse<T>>
```

##### `patch(path, body?, options?)`

Make a PATCH request.

```typescript
async patch<T = any>(
  path: string,
  body?: any,
  options?: RequestOptions
): Promise<QiuthResponse<T>>
```

---

## Validators

### IpValidator

Validates IP addresses against an allowlist.

#### Constructor

```typescript
constructor(config: IpAllowlistConfig)
```

**Parameters:**
- `config: IpAllowlistConfig`
  - `enabled: boolean` - Must be `true`
  - `allowedIps: string[]` - Array of IP addresses and CIDR ranges
  - `trustProxy?: boolean` - Trust proxy headers (default: `false`)

**Throws:** `Error` if config is invalid

#### Methods

##### `isAllowed(ip, headers?)`

Check if an IP address is allowed.

```typescript
isAllowed(
  ip: string,
  headers?: Record<string, string | string[] | undefined>
): boolean
```

**Parameters:**
- `ip: string` - IP address to check
- `headers?: Record<string, string | string[] | undefined>` - Request headers

**Returns:** `boolean` - `true` if allowed, `false` otherwise

**Example:**
```typescript
const validator = new IpValidator({
  enabled: true,
  allowedIps: ['192.168.1.0/24'],
  trustProxy: true,
});

const allowed = validator.isAllowed('192.168.1.100', {
  'x-forwarded-for': '203.0.113.1, 192.168.1.100',
});
```

---

### TotpValidator

Validates TOTP tokens (RFC 6238).

#### Constructor

```typescript
constructor(config: TotpConfig)
```

**Parameters:**
- `config: TotpConfig`
  - `enabled: boolean` - Must be `true`
  - `secret: string` - Base32-encoded TOTP secret
  - `timeStep?: number` - Time step in seconds (default: `30`)
  - `window?: number` - Drift tolerance (default: `1`)

**Throws:** `Error` if config is invalid

#### Methods

##### `validate(token, timestamp?)`

Validate a TOTP token.

```typescript
validate(token: string, timestamp?: number): boolean
```

**Parameters:**
- `token: string` - 6-digit TOTP token
- `timestamp?: number` - Unix timestamp in ms (default: current time)

**Returns:** `boolean` - `true` if valid, `false` otherwise

**Example:**
```typescript
const validator = new TotpValidator({
  enabled: true,
  secret: 'JBSWY3DPEHPK3PXP',
  timeStep: 30,
  window: 1,
});

const valid = validator.validate('123456');
```

##### `generate(timestamp?)`

Generate a TOTP token.

```typescript
generate(timestamp?: number): string
```

**Parameters:**
- `timestamp?: number` - Unix timestamp in ms (default: current time)

**Returns:** `string` - 6-digit TOTP token

**Example:**
```typescript
const token = validator.generate();
console.log(token); // "123456"
```

##### `generate(timestamp?)` (static)

Generate a TOTP token from a secret.

```typescript
static generate(
  secret: string,
  timestamp?: number,
  timeStep?: number
): string
```

**Parameters:**
- `secret: string` - Base32-encoded TOTP secret
- `timestamp?: number` - Unix timestamp in ms
- `timeStep?: number` - Time step in seconds (default: `30`)

**Returns:** `string` - 6-digit TOTP token

---

### CertificateValidator

Validates request signatures using RSA public keys.

#### Constructor

```typescript
constructor(config: CertificateConfig)
```

**Parameters:**
- `config: CertificateConfig`
  - `enabled: boolean` - Must be `true`
  - `publicKey: string` - PEM-encoded RSA public key
  - `maxAge?: number` - Max signature age in seconds (default: `300`)

**Throws:** `Error` if config is invalid

#### Methods

##### `verify(method, url, body, timestamp, signature)`

Verify a request signature.

```typescript
verify(
  method: string,
  url: string,
  body: string,
  timestamp: number,
  signature: string
): boolean
```

**Parameters:**
- `method: string` - HTTP method (GET, POST, etc.)
- `url: string` - Request URL
- `body: string` - Request body (empty string for GET)
- `timestamp: number` - Unix timestamp in ms
- `signature: string` - Base64-encoded signature

**Returns:** `boolean` - `true` if valid, `false` otherwise

##### `sign(privateKey, method, url, body, timestamp)` (static)

Sign a request.

```typescript
static sign(
  privateKey: string,
  method: string,
  url: string,
  body: string,
  timestamp: number
): string
```

**Parameters:**
- `privateKey: string` - PEM-encoded RSA private key
- `method: string` - HTTP method
- `url: string` - Request URL
- `body: string` - Request body
- `timestamp: number` - Unix timestamp in ms

**Returns:** `string` - Base64-encoded signature

**Example:**
```typescript
const signature = CertificateValidator.sign(
  privateKey,
  'POST',
  'https://api.example.com/users',
  JSON.stringify({ name: 'Alice' }),
  Date.now()
);
```

---

### HmacValidator

Validates request signatures using HMAC-SHA256 with a shared secret. A lighter-weight alternative to certificate-based authentication.

#### Constructor

```typescript
constructor(config: HmacConfig)
```

**Parameters:**
- `config: HmacConfig`
  - `enabled: boolean` - Must be `true`
  - `secret: string` - Shared secret (minimum 32 characters)
  - `maxAge?: number` - Max signature age in seconds (default: `300`)

**Throws:** `Error` if config is invalid or secret is too short

#### Methods

##### `verify(signature, method, url, body, timestamp)`

Verify an HMAC signature.

```typescript
verify(
  signature: string,
  method: string,
  url: string,
  body?: string | Buffer,
  timestamp?: string | number
): boolean
```

**Parameters:**
- `signature: string` - Hex-encoded HMAC signature
- `method: string` - HTTP method (GET, POST, etc.)
- `url: string` - Request URL
- `body?: string | Buffer` - Request body
- `timestamp?: string | number` - Unix timestamp in ms or ISO 8601 string

**Returns:** `boolean` - `true` if valid, `false` otherwise

##### `sign(secret, method, url, body, timestamp)` (static)

Sign a request.

```typescript
static sign(
  secret: string,
  method: string,
  url: string,
  body?: string | Buffer,
  timestamp?: number
): string
```

**Parameters:**
- `secret: string` - Shared secret
- `method: string` - HTTP method
- `url: string` - Request URL
- `body?: string | Buffer` - Request body
- `timestamp?: number` - Unix timestamp in ms (defaults to current time)

**Returns:** `string` - Hex-encoded HMAC signature

**Example:**
```typescript
import { HmacValidator } from 'qiuth';

// Generate a secret
const secret = HmacValidator.generateSecret();

// Sign a request
const timestamp = Date.now();
const signature = HmacValidator.sign(
  secret,
  'POST',
  'https://api.example.com/users',
  JSON.stringify({ name: 'Alice' }),
  timestamp
);

// Verify on server
const validator = new HmacValidator({
  enabled: true,
  secret: secret,
});

const isValid = validator.verify(
  signature,
  'POST',
  'https://api.example.com/users',
  JSON.stringify({ name: 'Alice' }),
  timestamp
);
```

##### `generateSecret(length?)` (static)

Generate a cryptographically secure shared secret.

```typescript
static generateSecret(length?: number): string
```

**Parameters:**
- `length?: number` - Length in bytes (default: `32`)

**Returns:** `string` - Hex-encoded secret (64 characters for 32 bytes)

##### `getMaxAge()`

Get the maximum signature age.

```typescript
getMaxAge(): number
```

**Returns:** `number` - Max age in seconds

##### `isTimestampAcceptable(timestamp)`

Check if a timestamp is within the acceptable range.

```typescript
isTimestampAcceptable(timestamp: string | number): boolean
```

**Parameters:**
- `timestamp: string | number` - Timestamp to check

**Returns:** `boolean` - `true` if acceptable

---

## Middleware

### createQiuthMiddleware

Create Express middleware for Qiuth authentication.

```typescript
function createQiuthMiddleware(
  options: QiuthMiddlewareOptions
): (req: Request, res: Response, next: NextFunction) => Promise<void>
```

**Parameters:**
- `options: QiuthMiddlewareOptions`
  - `configLookup: ConfigLookupFunction` - Function to lookup config by API key
  - `apiKeyHeader?: string` - Header name for API key (default: `'x-api-key'`)
  - `apiKeyQuery?: string` - Query param name (default: `'api_key'`)
  - `allowQueryKey?: boolean` - Allow API key in query (default: `false`)
  - `onError?: (error, req, res) => void` - Custom error handler
  - `onSuccess?: (result, req, res, next) => void` - Custom success handler
  - `debug?: boolean` - Enable debug logging
  - `logger?: (message: string) => void` - Custom logger
  - `collectMetrics?: boolean` - Enable metrics

**Returns:** Express middleware function

**Example:**
```typescript
import express from 'express';
import { createQiuthMiddleware } from 'qiuth';

const app = express();

const qiuthMiddleware = createQiuthMiddleware({
  configLookup: async (apiKey) => {
    // Lookup config from database
    return await db.getConfigByApiKey(apiKey);
  },
  apiKeyHeader: 'x-api-key',
  allowQueryKey: false,
  onError: (error, req, res) => {
    res.status(401).json({ error: error.errors });
  },
});

app.use('/api', qiuthMiddleware);

app.get('/api/protected', (req, res) => {
  // req.qiuth contains authentication info
  res.json({ message: 'Authenticated!' });
});
```

---

## Credential Management

### CredentialRotator

Manages zero-downtime credential rotation.

#### Constructor

```typescript
constructor(options?: CredentialRotatorOptions)
```

**Parameters:**
- `options?: CredentialRotatorOptions`
  - `transitionPeriod?: number` - Transition period in ms (default: `86400000` = 24 hours)
  - `onRotationStart?: (type, oldValue, newValue) => void` - Rotation start callback
  - `onRotationComplete?: (type) => void` - Rotation complete callback
  - `onRevocation?: (type, reason) => void` - Revocation callback

#### Methods

##### `rotateApiKey(currentKey, newKey?)`

Rotate an API key.

```typescript
async rotateApiKey(
  currentKey: string,
  newKey?: string
): Promise<CredentialRotationResult>
```

**Parameters:**
- `currentKey: string` - Current API key
- `newKey?: string` - New API key (generated if not provided)

**Returns:** `Promise<CredentialRotationResult>`
- `oldValue: string` - Old credential
- `newValue: string` - New credential
- `transitionEndsAt: Date` - When transition period ends
- `state: CredentialRotationState` - Current state

##### `rotateTotp(currentSecret, newSecret?)`

Rotate TOTP secret.

```typescript
async rotateTotp(
  currentSecret: string,
  newSecret?: string
): Promise<CredentialRotationResult>
```

##### `rotateCertificate(currentPublicKey, newKeyPair?)`

Rotate certificate key pair.

```typescript
async rotateCertificate(
  currentPublicKey: string,
  newKeyPair?: { publicKey: string; privateKey: string }
): Promise<CredentialRotationResult>
```

##### `revokeApiKey(apiKey, reason)`

Emergency revoke an API key.

```typescript
async revokeApiKey(
  apiKey: string,
  reason: string
): Promise<void>
```

---

## Observability

### Logger

Structured logging for Qiuth.

#### Functions

##### `createLogger(options?)`

Create a new logger instance.

```typescript
function createLogger(options?: LoggerOptions): Logger
```

**Parameters:**
- `options?: LoggerOptions`
  - `level?: LogLevel` - Minimum log level (default: `LogLevel.INFO`)
  - `output?: (entry: LogEntry) => void` - Custom output function
  - `includeTimestamp?: boolean` - Include timestamps (default: `true`)
  - `includeLevel?: boolean` - Include log levels (default: `true`)

**Returns:** `Logger` instance

**Example:**
```typescript
import { createLogger, LogLevel } from 'qiuth';

const logger = createLogger({
  level: LogLevel.DEBUG,
  output: (entry) => console.log(JSON.stringify(entry)),
});

logger.info('Authentication successful', { userId: '123' });
```

### MetricsCollector

Collect and export metrics.

#### Functions

##### `createMetricsCollector()`

Create a new metrics collector.

```typescript
function createMetricsCollector(): MetricsCollector
```

**Returns:** `MetricsCollector` instance

**Example:**
```typescript
import { createMetricsCollector } from 'qiuth';

const metrics = createMetricsCollector();

metrics.increment('auth.success');
metrics.timing('auth.duration', 150);

const report = metrics.getMetrics();
console.log(report);
```

---

## Utilities

### Crypto Functions

#### `generateApiKey(length?)`

Generate a secure random API key.

```typescript
function generateApiKey(length?: number): string
```

**Parameters:**
- `length?: number` - Key length (default: `32`)

**Returns:** `string` - Hex-encoded API key

#### `generateTotpSecret()`

Generate a Base32-encoded TOTP secret.

```typescript
function generateTotpSecret(): string
```

**Returns:** `string` - Base32-encoded secret

#### `generateKeyPair(options?)`

Generate an RSA key pair.

```typescript
function generateKeyPair(options?: {
  modulusLength?: number;
}): { publicKey: string; privateKey: string }
```

**Parameters:**
- `options?.modulusLength?: number` - Key size in bits (default: `2048`)

**Returns:** Object with PEM-encoded keys
- `publicKey: string` - PEM-encoded public key
- `privateKey: string` - PEM-encoded private key

### Config Loader

#### `loadFromEnv()`

Load configuration from environment variables.

```typescript
function loadFromEnv(): QiuthConfig
```

**Environment Variables:**
- `QIUTH_API_KEY` - API key (will be hashed)
- `QIUTH_IP_ALLOWLIST` - Comma-separated IPs/CIDRs
- `QIUTH_TRUST_PROXY` - "true" or "false"
- `QIUTH_TOTP_SECRET` - Base32-encoded TOTP secret
- `QIUTH_TOTP_TIME_STEP` - Time step in seconds
- `QIUTH_TOTP_WINDOW` - Drift tolerance
- `QIUTH_CERTIFICATE_PUBLIC_KEY` - PEM-encoded public key
- `QIUTH_CERTIFICATE_MAX_AGE` - Max signature age in seconds

**Returns:** `QiuthConfig`

**Throws:** `Error` if required variables are missing

---

## Types & Interfaces

See [src/types.ts](../src/types.ts) for complete type definitions.

### Key Types

- `SecurityLayer` - Enum of security layers
- `ValidationErrorType` - Enum of error types
- `QiuthConfig` - Complete configuration
- `AuthenticationRequest` - Request to authenticate
- `ValidationResult` - Authentication result
- `LayerValidationResult` - Per-layer result

---

## Version

Current version: **0.1.0**

```typescript
import { VERSION } from 'qiuth';
console.log(VERSION); // "0.1.0"
```

