import { describe, it, expect, vi } from 'vitest';
import { createQiuthFastifyPreHandler, QiuthFastifyAuth } from '../../src/middleware/fastify';
import { QiuthConfig } from '../../src/types';
import { QiuthAuthenticator } from '../../src/core/authenticator';
import type { FastifyRequest, FastifyReply } from 'fastify';

describe('Fastify Middleware', () => {
  const TEST_API_KEY = 'test-api-key-12345';
  const TEST_CONFIG: QiuthConfig = {
    hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
    ipAllowlist: {
      enabled: true,
      allowedIps: ['192.168.1.0/24'],
    },
  };

  function createMockRequest(overrides: Partial<FastifyRequest> = {}): FastifyRequest {
    return {
      headers: {},
      query: {},
      body: undefined,
      method: 'GET',
      url: '/test',
      protocol: 'https',
      hostname: 'api.example.com',
      ip: '192.168.1.100',
      socket: { remoteAddress: '192.168.1.100' },
      ...overrides,
    } as unknown as FastifyRequest;
  }

  function createMockReply(): FastifyReply {
    const reply = {
      status: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
      code: vi.fn().mockReturnThis(),
    };
    return reply as unknown as FastifyReply;
  }

  describe('API key extraction', () => {
    it('should extract API key from header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
      expect(req.qiuth).toBeDefined();
    });

    it('should extract API key from custom header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({
        configLookup,
        apiKeyHeader: 'authorization',
      });

      const req = createMockRequest({
        headers: { authorization: TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should extract API key from query when allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({
        configLookup,
        allowQueryKey: true,
      });

      const req = createMockRequest({
        query: { api_key: TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should not extract API key from query when not allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({
        configLookup,
        allowQueryKey: false,
      });

      const req = createMockRequest({
        query: { api_key: TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(reply.status).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Authentication failed',
        })
      );
    });

    it('should return 401 when API key is missing', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest();
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(reply.status).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'API key is required',
        })
      );
    });
  });

  describe('configuration lookup', () => {
    it('should call configLookup with API key', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should return 401 when config is not found', async () => {
      const configLookup = vi.fn().mockResolvedValue(null);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': 'unknown-key' },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(reply.status).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid API key',
        })
      );
    });

    it('should handle synchronous configLookup', async () => {
      const configLookup = vi.fn().mockReturnValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(req.qiuth).toBeDefined();
    });
  });

  describe('authentication', () => {
    it('should authenticate successfully with valid credentials', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        ip: '192.168.1.100',
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(req.qiuth).toBeDefined();
      expect(req.qiuth?.result.success).toBe(true);
    });

    it('should fail authentication with invalid IP', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        ip: '10.0.0.1', // Not in allowlist
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(reply.status).toHaveBeenCalledWith(401);
    });

    it('should attach qiuth object to request on success', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(req.qiuth).toBeDefined();
      expect(req.qiuth?.apiKey).toBe(TEST_API_KEY);
      expect(req.qiuth?.config).toBe(TEST_CONFIG);
      expect(req.qiuth?.result).toBeDefined();
    });
  });

  describe('custom handlers', () => {
    it('should call custom error handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onError = vi.fn();
      const preHandler = createQiuthFastifyPreHandler({ configLookup, onError });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        ip: '10.0.0.1', // Invalid IP
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(onError).toHaveBeenCalled();
      expect(reply.status).not.toHaveBeenCalled();
    });

    it('should call custom success handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onSuccess = vi.fn();
      const preHandler = createQiuthFastifyPreHandler({ configLookup, onSuccess });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(onSuccess).toHaveBeenCalled();
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
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-totp-token': '123456',
        },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      // Should fail because token is invalid, but it was extracted
      expect(reply.status).toHaveBeenCalledWith(401);
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
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-signature': 'dummy-signature',
          'x-timestamp': Date.now().toString(),
        },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      // Should fail because signature is invalid, but it was extracted
      expect(reply.status).toHaveBeenCalledWith(401);
    });

    it('should serialize JSON body', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        body: { data: 'test' },
        method: 'POST',
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(req.qiuth).toBeDefined();
    });
  });

  describe('error handling', () => {
    it('should handle internal errors gracefully', async () => {
      const configLookup = vi.fn().mockRejectedValue(new Error('Database error'));
      const preHandler = createQiuthFastifyPreHandler({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const reply = createMockReply();

      await preHandler(req, reply);

      expect(reply.status).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Authentication failed',
        })
      );
    });
  });
});
