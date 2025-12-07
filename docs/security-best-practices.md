# Security Best Practices

This guide outlines security best practices for implementing and operating Qiuth in production environments.

## Table of Contents

- [API Key Management](#api-key-management)
- [Layer Configuration](#layer-configuration)
- [Secret Storage](#secret-storage)
- [Transport Security](#transport-security)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Credential Rotation](#credential-rotation)
- [Incident Response](#incident-response)

---

## API Key Management

### Generation

**Use cryptographically secure random generation:**

```typescript
import { generateApiKey } from 'qiuth';

// Default: 32 bytes (256 bits) - sufficient for most use cases
const apiKey = generateApiKey();

// For higher security requirements: 64 bytes (512 bits)
const highSecurityKey = generateApiKey(64);
```

**Recommendations:**
- Minimum 32 bytes (256 bits) for production keys
- Generate keys server-side only, never client-side
- Never reuse keys across environments (dev/staging/prod)
- Include environment prefix in keys for easy identification: `prod_`, `staging_`, `dev_`

### Storage

**Server-side (storing hashed keys):**

```typescript
import { QiuthAuthenticator } from 'qiuth';

// Always store hashed keys, never plaintext
const hashedKey = QiuthAuthenticator.hashApiKey(apiKey);

// Store in database
await db.apiKeys.create({
  hashedKey,
  createdAt: new Date(),
  lastUsedAt: null,
  metadata: { /* ... */ }
});
```

**Client-side (storing plaintext keys):**
- Use environment variables, never hardcode in source
- Use secret managers (AWS Secrets Manager, HashiCorp Vault, etc.)
- Never commit keys to version control
- Never log keys in application logs

### Scoping

**Principle of least privilege:**
- Create separate API keys for each service/integration
- Assign minimum necessary permissions to each key
- Use different keys for read-only vs write operations
- Revoke keys immediately when access is no longer needed

---

## Layer Configuration

### Recommended Configurations by Use Case

**Internal Service-to-Service (trusted network):**

```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withIpAllowlist(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
  .withHmac(hmacSecret, 300) // 5-minute window
  .build();
```

**External Partner Integration:**

```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withIpAllowlist(partnerIpRanges, true) // Trust proxy headers
  .withTotp(totpSecret)
  .withCertificate(publicKey, 300)
  .build();
```

**Public API with Rate Limiting:**

```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withTotp(totpSecret) // MFA without IP restriction
  .build();
```

**High-Security Financial/Healthcare:**

```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withIpAllowlist(strictIpList)
  .withTotp(totpSecret, 30, 0) // No drift tolerance
  .withCertificate(publicKey, 60) // 1-minute window
  .build();
```

### IP Allowlisting Best Practices

**Be specific:**
```typescript
// Avoid overly broad ranges
.withIpAllowlist(['0.0.0.0/0']) // DO NOT DO THIS

// Be as specific as possible
.withIpAllowlist([
  '203.0.113.10',        // Specific IPs when possible
  '203.0.113.0/28',      // Smallest necessary CIDR
])
```

**Consider proxy configuration:**
```typescript
// Only trust proxy headers when behind a trusted load balancer
.withIpAllowlist(ips, true) // trustProxy = true

// Validate your load balancer strips/rewrites X-Forwarded-For
// Untrusted proxies can spoof these headers
```

### TOTP Configuration

**Recommended settings:**

```typescript
// Standard configuration
.withTotp(secret, 30, 1) // 30s window, +/- 1 step tolerance

// Strict configuration (no drift tolerance)
.withTotp(secret, 30, 0) // Requires precise time sync

// Extended tolerance for high-latency environments
.withTotp(secret, 30, 2) // +/- 2 steps (90 second total window)
```

**Time synchronization:**
- Ensure all servers use NTP
- Consider network latency in window configuration
- Monitor for clock drift issues

### Request Signing Best Practices

**HMAC vs Certificates:**

| Consideration | Use HMAC | Use Certificates |
|--------------|----------|------------------|
| Key management | Both parties secure | Server only needs public key |
| Setup complexity | Simple | More complex |
| Key rotation | Must coordinate | Can rotate independently |
| Non-repudiation | No | Yes |
| Internal services | Recommended | Overkill |
| External partners | Acceptable | Recommended |

**Timestamp window:**

```typescript
// Default: 5 minutes (300 seconds)
.withHmac(secret, 300)
.withCertificate(publicKey, 300)

// Stricter: 1 minute (60 seconds)
// Requires good time sync, may fail with network latency
.withHmac(secret, 60)

// Looser: 10 minutes (600 seconds)
// More tolerant but increases replay window
.withHmac(secret, 600)
```

---

## Secret Storage

### Environment Variables

**Development:**
```bash
# .env file (never commit to version control)
QIUTH_API_KEY=dev_abc123
QIUTH_TOTP_SECRET=JBSWY3DPEHPK3PXP
QIUTH_HMAC_SECRET=64-character-hex-string-here
```

**Production:**
- Use your platform's secret management:
  - AWS: Secrets Manager or Parameter Store
  - GCP: Secret Manager
  - Azure: Key Vault
  - Kubernetes: External Secrets Operator
  - HashiCorp Vault

### Secret Managers Integration

**AWS Secrets Manager example:**

```typescript
import { SecretsManager } from '@aws-sdk/client-secrets-manager';

const secretsManager = new SecretsManager();

async function getQiuthSecrets() {
  const { SecretString } = await secretsManager.getSecretValue({
    SecretId: 'prod/qiuth/secrets'
  });
  return JSON.parse(SecretString);
}

// Load at startup, cache in memory
const secrets = await getQiuthSecrets();
const config = new QiuthConfigBuilder()
  .withApiKey(secrets.apiKey)
  .withHmac(secrets.hmacSecret)
  .build();
```

### Private Key Storage

**RSA private keys require extra protection:**

```typescript
// Load from file with restricted permissions (chmod 600)
const privateKey = fs.readFileSync('/secure/path/qiuth-private.pem', 'utf8');

// Or use hardware security modules (HSM) for highest security
```

**File permissions:**
```bash
# Restrict private key file access
chmod 600 /path/to/qiuth-private.pem
chown app-user:app-group /path/to/qiuth-private.pem
```

---

## Transport Security

### TLS Requirements

**Always use HTTPS in production:**
- TLS 1.2 minimum, TLS 1.3 preferred
- Strong cipher suites only
- Valid certificates from trusted CAs

**Header security:**

```typescript
// Express example with helmet
import helmet from 'helmet';

app.use(helmet({
  strictTransportSecurity: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));
```

### API Key Transmission

**Headers (recommended):**
```typescript
// Use custom header
headers: { 'X-API-Key': apiKey }

// Or Authorization header
headers: { 'Authorization': `Bearer ${apiKey}` }
```

**Query parameters (avoid):**
```typescript
// Avoid - can be logged in access logs, browser history
.withApiKeyQuery('api_key') // Only enable if absolutely necessary
```

---

## Monitoring and Alerting

### Key Metrics to Track

```typescript
import { createMetricsCollector } from 'qiuth';

const metrics = createMetricsCollector();

// Track authentication attempts
metrics.increment('auth.attempts');
metrics.increment(result.success ? 'auth.success' : 'auth.failure');

// Track by layer
result.layerResults.forEach(layer => {
  metrics.increment(`auth.layer.${layer.layer}.${layer.valid ? 'pass' : 'fail'}`);
});

// Track timing
metrics.timing('auth.duration', result.duration);
```

### Alert Conditions

**Set up alerts for:**

1. **High failure rate:** >10% authentication failures in 5 minutes
2. **IP allowlist failures:** Any failures from unexpected IP ranges
3. **TOTP failures:** Repeated TOTP failures (possible replay attack)
4. **Signature failures:** Invalid signatures (possible tampering)
5. **Old timestamps:** Requests with timestamps outside window

### Logging Best Practices

```typescript
// DO log:
logger.info('Authentication attempt', {
  correlationId: result.correlationId,
  success: result.success,
  clientIp: request.clientIp,
  layers: result.layerResults.map(l => l.layer),
  duration: result.duration,
});

// DO NOT log:
logger.info('Auth', {
  apiKey: request.apiKey,      // NEVER log API keys
  totpToken: request.totpToken, // NEVER log TOTP tokens
  signature: request.signature, // NEVER log signatures
  hmacSecret: config.hmac.secret, // NEVER log secrets
});
```

---

## Credential Rotation

### Rotation Strategy

**Regular rotation schedule:**
- API keys: Every 90 days (or more frequently for high-security)
- TOTP secrets: Every 180 days
- HMAC secrets: Every 90 days
- RSA key pairs: Every 365 days

### Zero-Downtime Rotation

```typescript
import { CredentialRotator } from 'qiuth';

const rotator = new CredentialRotator({
  transitionPeriod: 86400000, // 24 hours
  onRotationStart: (type, old, new) => {
    logger.info(`Starting ${type} rotation`);
  },
  onRotationComplete: (type) => {
    logger.info(`Completed ${type} rotation`);
  },
});

// Start rotation - both old and new credentials valid during transition
await rotator.rotateApiKey(currentKey, newKey);

// After transition period, old credentials are automatically invalidated
```

### Rotation Checklist

1. Generate new credentials
2. Update server configuration to accept both old and new
3. Notify dependent services of upcoming rotation
4. Update clients with new credentials
5. Monitor for authentication failures
6. After transition period, remove old credentials
7. Confirm all clients are using new credentials
8. Invalidate old credentials

---

## Incident Response

### Suspected Key Compromise

**Immediate actions:**

```typescript
// 1. Revoke compromised key immediately
await rotator.revokeApiKey(compromisedKey, 'Suspected compromise');

// 2. Generate new key
const newKey = generateApiKey();

// 3. Update all clients (no transition period in emergencies)
// 4. Review access logs for unauthorized access
// 5. Investigate source of compromise
```

### Investigation Queries

```sql
-- Find all requests with compromised key
SELECT * FROM access_logs
WHERE api_key_hash = 'compromised_hash'
ORDER BY timestamp DESC;

-- Find unusual IP addresses
SELECT client_ip, COUNT(*) as attempts
FROM access_logs
WHERE api_key_hash = 'compromised_hash'
GROUP BY client_ip;

-- Find requests outside normal hours
SELECT * FROM access_logs
WHERE api_key_hash = 'compromised_hash'
AND HOUR(timestamp) NOT BETWEEN 9 AND 17;
```

### Post-Incident Actions

1. Document timeline of events
2. Identify root cause of compromise
3. Implement preventive measures
4. Update rotation schedule if needed
5. Consider adding additional security layers
6. Review and update access patterns

---

## Security Checklist

### Pre-Production

- [ ] All API keys generated with sufficient entropy (32+ bytes)
- [ ] API keys stored hashed, never plaintext
- [ ] Secrets stored in secret manager, not environment files
- [ ] IP allowlists configured as narrowly as possible
- [ ] TOTP or request signing enabled for all production keys
- [ ] TLS 1.2+ enforced for all API traffic
- [ ] Logging configured without exposing secrets
- [ ] Monitoring and alerting configured
- [ ] Rotation procedures documented and tested
- [ ] Incident response plan documented

### Ongoing Operations

- [ ] Regular credential rotation (per schedule)
- [ ] Monitor authentication failure rates
- [ ] Review and update IP allowlists as infrastructure changes
- [ ] Audit unused/stale API keys and revoke
- [ ] Test incident response procedures periodically
- [ ] Keep Qiuth library updated for security patches

---

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [NIST Special Publication 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CIS Controls](https://www.cisecurity.org/controls)
