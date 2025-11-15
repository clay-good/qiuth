# Basic Express Example

This example demonstrates how to use Qiuth middleware to protect Express routes with API key authentication.

## Features

- Express server with Qiuth middleware
- API key authentication
- IP allowlisting
- Multiple protected routes
- Error handling
- Request logging

## Setup

1. Install dependencies:
```bash
npm install
```

2. Build the project:
```bash
npm run build
```

3. Run the example:
```bash
cd examples/basic-express
npx ts-node server.ts
```

## Usage

The server will start on `http://localhost:3000` and display the API key to use for testing.

### Test Endpoints

1. **Root endpoint** (no auth required):
```bash
curl http://localhost:3000/
```

2. **Public API** (auth required):
```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:3000/api/public
```

3. **Protected API** (auth required):
```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:3000/api/protected
```

4. **POST data** (auth required):
```bash
curl -X POST \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"test":"data"}' \
  http://localhost:3000/api/data
```

5. **Without API key** (should fail):
```bash
curl http://localhost:3000/api/public
```

## Configuration

The example uses:
- **API Key**: Generated on startup
- **IP Allowlist**: `0.0.0.0/0` (allows all IPs for demo purposes)

In production, you should:
- Load API keys from environment variables or secure storage
- Restrict IP allowlist to known IP ranges
- Add TOTP and/or certificate authentication
- Implement rate limiting
- Use HTTPS

## Code Structure

```typescript
// Create configuration
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withIpAllowlist(['0.0.0.0/0'])
  .build();

// Create middleware
const qiuthAuth = createQiuthMiddleware({
  config,
  extractApiKey: (req) => req.headers['x-api-key'],
  extractClientIp: (req) => req.ip,
  onSuccess: (req, res, result) => {
    console.log('Auth successful');
  },
  onFailure: (req, res, result) => {
    console.error('Auth failed:', result.errors);
  },
});

// Apply to routes
app.get('/api/protected', qiuthAuth, (req, res) => {
  res.json({ message: 'Access granted!' });
});
```

## Next Steps

- Add TOTP authentication (see `examples/mfa-service/`)
- Add certificate authentication (see `examples/certificate-auth/`)
- Implement credential rotation (see `examples/credential-rotation/`)
- Add monitoring and metrics (see `examples/monitoring/`)

