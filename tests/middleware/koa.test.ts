import { describe, it, expect, vi } from 'vitest';
import { createQiuthKoaMiddleware } from '../../src/middleware/koa';
import { QiuthConfig } from '../../src/types';
import { QiuthAuthenticator } from '../../src/core/authenticator';
import type { Context, Next } from 'koa';

describe('Koa Middleware', () => {
  const TEST_API_KEY = 'test-api-key-12345';
  const TEST_CONFIG: QiuthConfig = {
    hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
    ipAllowlist: {
      enabled: true,
      allowedIps: ['192.168.1.0/24'],
    },
  };

  function createMockContext(overrides: Partial<Context> = {}): Context {
    const ctx = {
      headers: {},
      query: {},
      request: { body: undefined },
      method: 'GET',
      url: '/test',
      href: 'https://api.example.com/test',
      protocol: 'https',
      host: 'api.example.com',
      ip: '192.168.1.100',
      socket: { remoteAddress: '192.168.1.100' },
      state: {},
      status: 200,
      body: undefined,
      get: vi.fn((name: string) => {
        const headers = (overrides.headers || {}) as Record<string, string>;
        return headers[name.toLowerCase()] || '';
      }),
      ...overrides,
    };
    return ctx as unknown as Context;
  }

  function createMockNext(): Next {
    return vi.fn().mockResolvedValue(undefined);
  }

  describe('API key extraction', () => {
    it('should extract API key from header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
      expect(next).toHaveBeenCalled();
    });

    it('should extract API key from custom header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({
        configLookup,
        apiKeyHeader: 'authorization',
      });

      const ctx = createMockContext();
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'authorization') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should extract API key from query when allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({
        configLookup,
        allowQueryKey: true,
      });

      const ctx = createMockContext({
        query: { api_key: TEST_API_KEY },
      });
      ctx.get = vi.fn(() => '');
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should not extract API key from query when not allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({
        configLookup,
        allowQueryKey: false,
      });

      const ctx = createMockContext({
        query: { api_key: TEST_API_KEY },
      });
      ctx.get = vi.fn(() => '');
      const next = createMockNext();

      await middleware(ctx, next);

      expect(ctx.status).toBe(401);
      expect(ctx.body).toEqual(
        expect.objectContaining({
          error: 'Authentication failed',
        })
      );
    });

    it('should return 401 when API key is missing', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext();
      ctx.get = vi.fn(() => '');
      const next = createMockNext();

      await middleware(ctx, next);

      expect(ctx.status).toBe(401);
      expect(ctx.body).toEqual(
        expect.objectContaining({
          message: 'API key is required',
        })
      );
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('configuration lookup', () => {
    it('should call configLookup with API key', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext();
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should return 401 when config is not found', async () => {
      const configLookup = vi.fn().mockResolvedValue(null);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext();
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return 'unknown-key';
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(ctx.status).toBe(401);
      expect(ctx.body).toEqual(
        expect.objectContaining({
          message: 'Invalid API key',
        })
      );
    });

    it('should handle synchronous configLookup', async () => {
      const configLookup = vi.fn().mockReturnValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext();
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('authentication', () => {
    it('should authenticate successfully with valid credentials', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext({
        ip: '192.168.1.100',
      });
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(next).toHaveBeenCalled();
      expect(ctx.state.qiuth).toBeDefined();
      expect(ctx.state.qiuth?.result.success).toBe(true);
    });

    it('should fail authentication with invalid IP', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext({
        ip: '10.0.0.1', // Not in allowlist
      });
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(ctx.status).toBe(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should attach qiuth object to context state on success', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext();
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(ctx.state.qiuth).toBeDefined();
      expect(ctx.state.qiuth?.apiKey).toBe(TEST_API_KEY);
      expect(ctx.state.qiuth?.config).toBe(TEST_CONFIG);
      expect(ctx.state.qiuth?.result).toBeDefined();
    });
  });

  describe('custom handlers', () => {
    it('should call custom error handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onError = vi.fn();
      const middleware = createQiuthKoaMiddleware({ configLookup, onError });

      const ctx = createMockContext({
        ip: '10.0.0.1', // Invalid IP
      });
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(onError).toHaveBeenCalled();
    });

    it('should call custom success handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onSuccess = vi.fn();
      const middleware = createQiuthKoaMiddleware({ configLookup, onSuccess });

      const ctx = createMockContext();
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(onSuccess).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should handle internal errors gracefully', async () => {
      const configLookup = vi.fn().mockRejectedValue(new Error('Database error'));
      const middleware = createQiuthKoaMiddleware({ configLookup });

      const ctx = createMockContext();
      ctx.get = vi.fn((name: string) => {
        if (name.toLowerCase() === 'x-api-key') return TEST_API_KEY;
        return '';
      });
      const next = createMockNext();

      await middleware(ctx, next);

      expect(ctx.status).toBe(401);
      expect(ctx.body).toEqual(
        expect.objectContaining({
          error: 'Authentication failed',
        })
      );
    });
  });
});
