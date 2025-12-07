# Framework Middleware Integrations

Qiuth provides middleware for popular Node.js web frameworks. Each middleware follows the same authentication flow and configuration patterns while respecting framework-specific conventions.

## Supported Frameworks

| Framework | Function | Import |
|-----------|----------|--------|
| Express | `createQiuthMiddleware` | `import { createQiuthMiddleware } from 'qiuth'` |
| Fastify | `qiuthFastifyPlugin` / `createQiuthFastifyPreHandler` | `import { qiuthFastifyPlugin } from 'qiuth'` |
| Koa | `createQiuthKoaMiddleware` | `import { createQiuthKoaMiddleware } from 'qiuth'` |
| Hono | `createQiuthHonoMiddleware` | `import { createQiuthHonoMiddleware } from 'qiuth'` |

## Common Configuration

All middleware implementations share the same core options:

```typescript
interface CommonOptions {
  // Required: Function to lookup config by API key
  configLookup: (apiKey: string) => Promise<QiuthConfig | null> | QiuthConfig | null;

  // Optional: Header name for API key (default: 'x-api-key')
  apiKeyHeader?: string;

  // Optional: Query parameter name (default: 'api_key')
  apiKeyQuery?: string;

  // Optional: Allow API key in query params (default: false)
  allowQueryKey?: boolean;

  // Optional: Enable debug logging
  debug?: boolean;

  // Optional: Custom logger
  logger?: (message: string, ...args: unknown[]) => void;

  // Optional: Enable metrics collection
  collectMetrics?: boolean;

  // Optional: Custom error handler
  onError?: (error: ValidationResult, ...frameworkArgs) => void;

  // Optional: Custom success handler
  onSuccess?: (result: ValidationResult, ...frameworkArgs) => void;
}
```

## Express

Express middleware works as standard Connect-style middleware.

### Basic Usage

```typescript
import express from 'express';
import { createQiuthMiddleware, QiuthConfigBuilder } from 'qiuth';

const app = express();

// In-memory config lookup (use database in production)
const apiConfigs = new Map<string, QiuthConfig>();

const qiuthMiddleware = createQiuthMiddleware({
  configLookup: async (apiKey) => {
    return apiConfigs.get(apiKey) || null;
  },
});

// Apply to specific routes
app.get('/api/protected', qiuthMiddleware, (req, res) => {
  // Access auth info via req.qiuth
  res.json({
    message: 'Authenticated',
    apiKey: req.qiuth?.apiKey,
  });
});

app.listen(3000);
```

### With Database Lookup

```typescript
import { createQiuthMiddleware, QiuthConfigBuilder } from 'qiuth';

const qiuthMiddleware = createQiuthMiddleware({
  configLookup: async (apiKey) => {
    const record = await db.apiKeys.findOne({ key: apiKey });
    if (!record) return null;

    return new QiuthConfigBuilder()
      .withHashedApiKey(record.hashedKey)
      .withIpAllowlist(record.allowedIps)
      .withTotp(record.totpSecret)
      .build();
  },
  onError: (error, req, res) => {
    // Custom error response
    res.status(401).json({
      error: 'Unauthorized',
      code: 'AUTH_FAILED',
      requestId: req.headers['x-request-id'],
    });
  },
});
```

### TypeScript Types

```typescript
import { QiuthRequest } from 'qiuth';

app.get('/api/me', qiuthMiddleware, (req: QiuthRequest, res) => {
  // req.qiuth is typed
  const { apiKey, result, config } = req.qiuth!;
});
```

---

## Fastify

Qiuth provides both a Fastify plugin and a standalone preHandler.

### Plugin Usage

```typescript
import fastify from 'fastify';
import { qiuthFastifyPlugin } from 'qiuth';

const app = fastify();

// Register plugin
app.register(qiuthFastifyPlugin, {
  configLookup: async (apiKey) => {
    return await db.getApiKeyConfig(apiKey);
  },
});

// Use the decorated preHandler on specific routes
app.get('/protected', {
  preHandler: app.qiuthAuth,
}, async (request, reply) => {
  return {
    authenticated: true,
    apiKey: request.qiuth?.apiKey,
  };
});

app.listen({ port: 3000 });
```

### Standalone PreHandler

For more control, use the standalone preHandler function:

```typescript
import fastify from 'fastify';
import { createQiuthFastifyPreHandler } from 'qiuth';

const app = fastify();

const qiuthAuth = createQiuthFastifyPreHandler({
  configLookup: async (apiKey) => {
    return await db.getApiKeyConfig(apiKey);
  },
});

// Apply to specific routes
app.get('/protected', {
  preHandler: qiuthAuth,
}, async (request, reply) => {
  return { authenticated: true };
});

// Apply to route group
app.register(async (instance) => {
  instance.addHook('preHandler', qiuthAuth);

  instance.get('/users', async () => ({ users: [] }));
  instance.get('/posts', async () => ({ posts: [] }));
}, { prefix: '/api' });
```

### TypeScript Types

```typescript
import { FastifyRequest } from 'fastify';

// The plugin extends FastifyRequest with qiuth property
app.get('/me', { preHandler: app.qiuthAuth }, async (request: FastifyRequest, reply) => {
  const auth = request.qiuth;
  // auth is typed as QiuthFastifyAuth | undefined
});
```

---

## Koa

Koa middleware attaches authentication info to `ctx.state.qiuth`.

### Basic Usage

```typescript
import Koa from 'koa';
import Router from '@koa/router';
import { createQiuthKoaMiddleware } from 'qiuth';

const app = new Koa();
const router = new Router();

const qiuthMiddleware = createQiuthKoaMiddleware({
  configLookup: async (apiKey) => {
    return await db.getApiKeyConfig(apiKey);
  },
});

// Apply to all API routes
router.use('/api', qiuthMiddleware);

router.get('/api/protected', async (ctx) => {
  ctx.body = {
    authenticated: true,
    apiKey: ctx.state.qiuth?.apiKey,
  };
});

app.use(router.routes());
app.use(router.allowedMethods());

app.listen(3000);
```

### Per-Route Usage

```typescript
const qiuthMiddleware = createQiuthKoaMiddleware({
  configLookup: async (apiKey) => {
    return await db.getApiKeyConfig(apiKey);
  },
});

// Apply to specific route
router.get('/api/protected', qiuthMiddleware, async (ctx) => {
  ctx.body = { message: 'Authenticated' };
});

// Public route - no middleware
router.get('/api/public', async (ctx) => {
  ctx.body = { message: 'Public endpoint' };
});
```

### With Custom Error Handler

```typescript
const qiuthMiddleware = createQiuthKoaMiddleware({
  configLookup: async (apiKey) => {
    return await db.getApiKeyConfig(apiKey);
  },
  onError: async (error, ctx) => {
    ctx.status = 401;
    ctx.body = {
      error: 'Authentication required',
      details: error.errors,
      timestamp: new Date().toISOString(),
    };
  },
});
```

---

## Hono

Hono middleware works with Cloudflare Workers, Deno Deploy, Bun, and Node.js.

### Basic Usage

```typescript
import { Hono } from 'hono';
import { createQiuthHonoMiddleware } from 'qiuth';

const app = new Hono();

const qiuthMiddleware = createQiuthHonoMiddleware({
  configLookup: async (apiKey) => {
    return await db.getApiKeyConfig(apiKey);
  },
});

// Apply to route group
app.use('/api/*', qiuthMiddleware);

app.get('/api/protected', (c) => {
  const auth = c.get('qiuth');
  return c.json({
    authenticated: true,
    apiKey: auth?.apiKey,
  });
});

export default app;
```

### Cloudflare Workers with KV

```typescript
import { Hono } from 'hono';
import { createQiuthHonoMiddleware } from 'qiuth';

type Bindings = {
  API_KEYS: KVNamespace;
};

const app = new Hono<{ Bindings: Bindings }>();

// Create middleware per-request to access env bindings
app.use('/api/*', async (c, next) => {
  const qiuthMiddleware = createQiuthHonoMiddleware({
    configLookup: async (apiKey) => {
      // Lookup from Cloudflare KV
      const config = await c.env.API_KEYS.get(apiKey, 'json');
      return config;
    },
  });
  return qiuthMiddleware(c, next);
});

app.get('/api/data', (c) => {
  return c.json({ data: 'protected' });
});

export default app;
```

### Deno Deploy

```typescript
import { Hono } from 'https://deno.land/x/hono/mod.ts';
import { createQiuthHonoMiddleware } from 'qiuth';

const app = new Hono();

const qiuthMiddleware = createQiuthHonoMiddleware({
  configLookup: async (apiKey) => {
    // Use Deno KV or other storage
    const kv = await Deno.openKv();
    const result = await kv.get(['api_keys', apiKey]);
    return result.value as QiuthConfig | null;
  },
});

app.use('/api/*', qiuthMiddleware);

Deno.serve(app.fetch);
```

### Edge Environment Considerations

When running in edge environments:

1. **IP Detection**: The middleware checks `cf-connecting-ip`, `x-forwarded-for`, and `x-real-ip` headers automatically
2. **Body Reading**: Body is read asynchronously and may only be read once
3. **KV Lookups**: Create middleware per-request if you need access to environment bindings

---

## Authentication Headers

All middleware implementations expect authentication credentials in these headers:

| Header | Purpose | Required |
|--------|---------|----------|
| `x-api-key` | API key | Yes |
| `x-totp-token` | TOTP 6-digit code | If TOTP enabled |
| `x-signature` | Request signature (base64) | If certificate auth enabled |
| `x-timestamp` | Request timestamp (Unix ms) | If certificate auth enabled |

### Example Request

```bash
curl -X GET https://api.example.com/protected \
  -H "x-api-key: your-api-key" \
  -H "x-totp-token: 123456" \
  -H "x-timestamp: 1699900000000" \
  -H "x-signature: base64-encoded-signature"
```

---

## Error Responses

Default error responses follow this format:

```json
{
  "error": "Authentication failed",
  "message": "API key is required",
  "details": ["API key is required"],
  "correlationId": "uuid-for-tracing"
}
```

HTTP status code is 401 for all authentication failures.

---

## Migration Guide

### From Express to Fastify

```typescript
// Express
const middleware = createQiuthMiddleware({ configLookup });
app.use('/api', middleware);
// Access: req.qiuth

// Fastify
app.register(qiuthFastifyPlugin, { configLookup });
app.addHook('preHandler', app.qiuthAuth);
// Access: request.qiuth
```

### From Express to Koa

```typescript
// Express
const middleware = createQiuthMiddleware({ configLookup });
app.use('/api', middleware);
// Access: req.qiuth

// Koa
const middleware = createQiuthKoaMiddleware({ configLookup });
router.use('/api', middleware);
// Access: ctx.state.qiuth
```

### From Express to Hono

```typescript
// Express
const middleware = createQiuthMiddleware({ configLookup });
app.use('/api', middleware);
// Access: req.qiuth

// Hono
const middleware = createQiuthHonoMiddleware({ configLookup });
app.use('/api/*', middleware);
// Access: c.get('qiuth')
```
