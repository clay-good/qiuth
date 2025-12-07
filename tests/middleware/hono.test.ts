import { describe, it, expect, vi } from 'vitest';
import { createQiuthHonoMiddleware } from '../../src/middleware/hono';
import { QiuthConfig } from '../../src/types';
import { QiuthAuthenticator } from '../../src/core/authenticator';
import type { Context } from 'hono';

describe('Hono Middleware', () => {
  const TEST_API_KEY = 'test-api-key-12345';
  const TEST_IP = '192.168.1.100';
  const TEST_CONFIG: QiuthConfig = {
    hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
    ipAllowlist: {
      enabled: true,
      allowedIps: ['192.168.1.0/24'],
    },
  };
  const TEST_CONFIG_NO_IP: QiuthConfig = {
    hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
  };

  function createMockContext(overrides: {
    headers?: Record<string, string>;
    query?: Record<string, string>;
    method?: string;
    url?: string;
    body?: string;
  } = {}): Context {
    const headers = new Map(Object.entries(overrides.headers || {}));
    const variables = new Map<string, unknown>();

    const ctx = {
      req: {
        method: overrides.method || 'GET',
        url: overrides.url || 'https://api.example.com/test',
        header: vi.fn((name: string) => headers.get(name.toLowerCase())),
        query: vi.fn((name: string) => (overrides.query || {})[name]),
        text: vi.fn().mockResolvedValue(overrides.body || ''),
        raw: {
          headers: {
            entries: () => headers.entries(),
          },
        },
      },
      set: vi.fn((key: string, value: unknown) => {
        variables.set(key, value);
      }),
      get: vi.fn((key: string) => variables.get(key)),
      json: vi.fn((data: unknown, status?: number) => {
        return new Response(JSON.stringify(data), {
          status: status || 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    };

    return ctx as unknown as Context;
  }

  function createMockNext() {
    return vi.fn().mockResolvedValue(undefined);
  }

  describe('API key extraction', () => {
    it('should extract API key from header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG_NO_IP);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
      expect(next).toHaveBeenCalled();
    });

    it('should extract API key from custom header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG_NO_IP);
      const middleware = createQiuthHonoMiddleware({
        configLookup,
        apiKeyHeader: 'authorization',
      });

      const ctx = createMockContext({
        headers: { authorization: TEST_API_KEY },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should extract API key from query when allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG_NO_IP);
      const middleware = createQiuthHonoMiddleware({
        configLookup,
        allowQueryKey: true,
      });

      const ctx = createMockContext({
        query: { api_key: TEST_API_KEY },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should not extract API key from query when not allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG_NO_IP);
      const middleware = createQiuthHonoMiddleware({
        configLookup,
        allowQueryKey: false,
      });

      const ctx = createMockContext({
        query: { api_key: TEST_API_KEY },
      });
      const next = createMockNext();

      const response = await middleware(ctx, next);

      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(401);
    });

    it('should return 401 when API key is missing', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext();
      const next = createMockNext();

      const response = await middleware(ctx, next);

      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(401);
      const body = await (response as Response).json();
      expect(body.message).toBe('API key is required');
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('configuration lookup', () => {
    it('should call configLookup with API key', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG_NO_IP);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should return 401 when config is not found', async () => {
      const configLookup = vi.fn().mockResolvedValue(null);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: { 'x-api-key': 'unknown-key' },
      });
      const next = createMockNext();

      const response = await middleware(ctx, next);

      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(401);
      const body = await (response as Response).json();
      expect(body.message).toBe('Invalid API key');
    });

    it('should handle synchronous configLookup', async () => {
      const configLookup = vi.fn().mockReturnValue(TEST_CONFIG_NO_IP);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('authentication', () => {
    it('should authenticate successfully with valid credentials', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-forwarded-for': '192.168.1.100', // IP in allowlist
        },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(next).toHaveBeenCalled();
      expect(ctx.set).toHaveBeenCalledWith('qiuth', expect.objectContaining({
        apiKey: TEST_API_KEY,
      }));
    });

    it('should fail authentication with invalid IP from x-forwarded-for', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-forwarded-for': '10.0.0.1', // Not in allowlist
        },
      });
      const next = createMockNext();

      const response = await middleware(ctx, next);

      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should set qiuth variable on context on success', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-forwarded-for': '192.168.1.100', // IP in allowlist
        },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(ctx.set).toHaveBeenCalledWith('qiuth', expect.objectContaining({
        apiKey: TEST_API_KEY,
        config: TEST_CONFIG,
        result: expect.objectContaining({ success: true }),
      }));
    });
  });

  describe('custom handlers', () => {
    it('should call custom error handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onError = vi.fn().mockReturnValue(new Response('Custom error', { status: 403 }));
      const middleware = createQiuthHonoMiddleware({ configLookup, onError });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-forwarded-for': '10.0.0.1', // Invalid IP
        },
      });
      const next = createMockNext();

      const response = await middleware(ctx, next);

      expect(onError).toHaveBeenCalled();
      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(403);
    });

    it('should call custom success handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onSuccess = vi.fn();
      const middleware = createQiuthHonoMiddleware({ configLookup, onSuccess });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-forwarded-for': '192.168.1.100', // IP in allowlist
        },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(onSuccess).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });
  });

  describe('request parsing', () => {
    it('should extract TOTP token from header', async () => {
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        totp: {
          enabled: true,
          secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        },
      };
      const configLookup = vi.fn().mockResolvedValue(config);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-totp-token': '123456',
        },
      });
      const next = createMockNext();

      const response = await middleware(ctx, next);

      // Should fail because token is invalid, but it was extracted
      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(401);
    });

    it('should extract signature and timestamp from headers', async () => {
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        certificate: {
          enabled: true,
          publicKey: 'dummy-key',
        },
      };
      const configLookup = vi.fn().mockResolvedValue(config);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-signature': 'dummy-signature',
          'x-timestamp': Date.now().toString(),
        },
      });
      const next = createMockNext();

      const response = await middleware(ctx, next);

      // Should fail because signature is invalid, but it was extracted
      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(401);
    });
  });

  describe('error handling', () => {
    it('should handle internal errors gracefully', async () => {
      const configLookup = vi.fn().mockRejectedValue(new Error('Database error'));
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const next = createMockNext();

      const response = await middleware(ctx, next);

      expect(response).toBeInstanceOf(Response);
      expect((response as Response).status).toBe(401);
      const body = await (response as Response).json();
      expect(body.error).toBe('Authentication failed');
    });
  });

  describe('edge environment compatibility', () => {
    it('should handle cf-connecting-ip header for Cloudflare', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'cf-connecting-ip': '192.168.1.50',
        },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(next).toHaveBeenCalled();
    });

    it('should handle x-real-ip header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthHonoMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-real-ip': '192.168.1.50',
        },
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(next).toHaveBeenCalled();
    });
  });
});
