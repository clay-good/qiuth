/**
 * Fastify Plugin for Qiuth
 *
 * Provides authentication plugin for Fastify applications.
 * Extracts API keys, validates requests, and decorates request with authentication info.
 *
 * @packageDocumentation
 */

import type {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
  FastifyPluginCallback,
} from 'fastify';
import { QiuthAuthenticator } from '../core/authenticator';
import {
  QiuthConfig,
  AuthenticationRequest,
  ValidationResult,
  AuthenticatorOptions,
} from '../types';

/**
 * Qiuth authentication info attached to Fastify request
 */
export interface QiuthFastifyAuth {
  /** Validation result */
  result: ValidationResult;
  /** Validated configuration */
  config: QiuthConfig;
  /** API key used (not hashed) */
  apiKey: string;
}

/**
 * Configuration lookup function
 *
 * This function is called to retrieve the configuration for a given API key.
 * It should return the configuration or null if the key is not found.
 */
export type FastifyConfigLookupFunction = (
  apiKey: string
) => Promise<QiuthConfig | null> | QiuthConfig | null;

/**
 * Options for Qiuth Fastify plugin
 */
export interface QiuthFastifyOptions extends AuthenticatorOptions {
  /**
   * Function to lookup configuration for an API key
   * This is typically a database query
   */
  configLookup: FastifyConfigLookupFunction;

  /**
   * Header name for API key
   * @default 'x-api-key'
   */
  apiKeyHeader?: string;

  /**
   * Query parameter name for API key
   * @default 'api_key'
   */
  apiKeyQuery?: string;

  /**
   * Whether to allow API key in query parameters
   * @default false (more secure to use headers only)
   */
  allowQueryKey?: boolean;

  /**
   * Custom error handler
   * If not provided, sends JSON error response
   */
  onError?: (
    error: ValidationResult,
    request: FastifyRequest,
    reply: FastifyReply
  ) => void | Promise<void>;

  /**
   * Custom success handler
   * If not provided, continues to route handler
   */
  onSuccess?: (
    result: ValidationResult,
    request: FastifyRequest,
    reply: FastifyReply
  ) => void | Promise<void>;

  /**
   * Decorator name for attaching auth info to request
   * @default 'qiuth'
   */
  decoratorName?: string;
}

// Extend Fastify types
declare module 'fastify' {
  interface FastifyRequest {
    qiuth?: QiuthFastifyAuth;
  }
}

/**
 * Create Qiuth Fastify plugin
 *
 * @param options - Plugin options
 * @returns Fastify plugin
 *
 * @example
 * ```typescript
 * import fastify from 'fastify';
 * import { qiuthFastifyPlugin } from 'qiuth';
 *
 * const app = fastify();
 *
 * app.register(qiuthFastifyPlugin, {
 *   configLookup: async (apiKey) => {
 *     return await db.getApiKeyConfig(apiKey);
 *   },
 * });
 *
 * // Or use as a preHandler for specific routes
 * app.get('/protected', {
 *   preHandler: app.qiuthAuth,
 * }, async (request, reply) => {
 *   return { authenticated: true, apiKey: request.qiuth?.apiKey };
 * });
 * ```
 */
export const qiuthFastifyPlugin: FastifyPluginCallback<QiuthFastifyOptions> = (
  fastify: FastifyInstance,
  options: QiuthFastifyOptions,
  done: (err?: Error) => void
) => {
  const authenticator = new QiuthAuthenticator({
    debug: options.debug,
    logger: options.logger,
    collectMetrics: options.collectMetrics,
  });

  const apiKeyHeader = options.apiKeyHeader ?? 'x-api-key';
  const apiKeyQuery = options.apiKeyQuery ?? 'api_key';
  const allowQueryKey = options.allowQueryKey ?? false;
  const decoratorName = options.decoratorName ?? 'qiuth';

  // Decorate request with qiuth property
  if (!fastify.hasRequestDecorator(decoratorName)) {
    fastify.decorateRequest(decoratorName, null);
  }

  // Create the preHandler hook function
  const qiuthPreHandler = async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    try {
      // Extract API key
      const apiKey = extractApiKey(request, apiKeyHeader, apiKeyQuery, allowQueryKey);
      if (!apiKey) {
        const errorResult: ValidationResult = {
          success: false,
          errors: ['API key is required'],
          layerResults: [],
          validatedAt: new Date(),
        };
        await handleError(errorResult, request, reply, options.onError);
        return;
      }

      // Lookup configuration
      const config = await options.configLookup(apiKey);
      if (!config) {
        const errorResult: ValidationResult = {
          success: false,
          errors: ['Invalid API key'],
          layerResults: [],
          validatedAt: new Date(),
        };
        await handleError(errorResult, request, reply, options.onError);
        return;
      }

      // Build authentication request
      const authRequest: AuthenticationRequest = {
        apiKey,
        clientIp: extractClientIp(request),
        method: request.method,
        url: getFullUrl(request),
        body: getRequestBody(request),
        headers: request.headers as Record<string, string | string[] | undefined>,
        totpToken: extractTotpToken(request),
        signature: extractSignature(request),
        hmacSignature: extractHmacSignature(request),
        timestamp: extractTimestamp(request),
      };

      // Authenticate
      const result = await authenticator.authenticate(authRequest, config);

      if (result.success) {
        // Attach authentication info to request
        (request as FastifyRequest)[decoratorName as 'qiuth'] = {
          result,
          config,
          apiKey,
        };

        // Call success handler if provided
        if (options.onSuccess) {
          await options.onSuccess(result, request, reply);
        }
      } else {
        await handleError(result, request, reply, options.onError);
      }
    } catch (error) {
      const errorResult: ValidationResult = {
        success: false,
        errors: [`Internal error: ${error instanceof Error ? error.message : 'Unknown error'}`],
        layerResults: [],
        validatedAt: new Date(),
      };
      await handleError(errorResult, request, reply, options.onError);
    }
  };

  // Decorate fastify instance with the auth function for use as preHandler
  fastify.decorate('qiuthAuth', qiuthPreHandler);

  done();
};

/**
 * Create Qiuth preHandler hook for Fastify
 *
 * Alternative to plugin - creates a standalone preHandler function
 *
 * @param options - Options for the preHandler
 * @returns Fastify preHandler function
 *
 * @example
 * ```typescript
 * import fastify from 'fastify';
 * import { createQiuthFastifyPreHandler } from 'qiuth';
 *
 * const app = fastify();
 *
 * const qiuthAuth = createQiuthFastifyPreHandler({
 *   configLookup: async (apiKey) => {
 *     return await db.getApiKeyConfig(apiKey);
 *   },
 * });
 *
 * app.get('/protected', { preHandler: qiuthAuth }, async (request, reply) => {
 *   return { authenticated: true };
 * });
 * ```
 */
export function createQiuthFastifyPreHandler(
  options: QiuthFastifyOptions
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  const authenticator = new QiuthAuthenticator({
    debug: options.debug,
    logger: options.logger,
    collectMetrics: options.collectMetrics,
  });

  const apiKeyHeader = options.apiKeyHeader ?? 'x-api-key';
  const apiKeyQuery = options.apiKeyQuery ?? 'api_key';
  const allowQueryKey = options.allowQueryKey ?? false;

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    try {
      // Extract API key
      const apiKey = extractApiKey(request, apiKeyHeader, apiKeyQuery, allowQueryKey);
      if (!apiKey) {
        const errorResult: ValidationResult = {
          success: false,
          errors: ['API key is required'],
          layerResults: [],
          validatedAt: new Date(),
        };
        await handleError(errorResult, request, reply, options.onError);
        return;
      }

      // Lookup configuration
      const config = await options.configLookup(apiKey);
      if (!config) {
        const errorResult: ValidationResult = {
          success: false,
          errors: ['Invalid API key'],
          layerResults: [],
          validatedAt: new Date(),
        };
        await handleError(errorResult, request, reply, options.onError);
        return;
      }

      // Build authentication request
      const authRequest: AuthenticationRequest = {
        apiKey,
        clientIp: extractClientIp(request),
        method: request.method,
        url: getFullUrl(request),
        body: getRequestBody(request),
        headers: request.headers as Record<string, string | string[] | undefined>,
        totpToken: extractTotpToken(request),
        signature: extractSignature(request),
        hmacSignature: extractHmacSignature(request),
        timestamp: extractTimestamp(request),
      };

      // Authenticate
      const result = await authenticator.authenticate(authRequest, config);

      if (result.success) {
        // Attach authentication info to request
        request.qiuth = {
          result,
          config,
          apiKey,
        };

        // Call success handler if provided
        if (options.onSuccess) {
          await options.onSuccess(result, request, reply);
        }
      } else {
        await handleError(result, request, reply, options.onError);
      }
    } catch (error) {
      const errorResult: ValidationResult = {
        success: false,
        errors: [`Internal error: ${error instanceof Error ? error.message : 'Unknown error'}`],
        layerResults: [],
        validatedAt: new Date(),
      };
      await handleError(errorResult, request, reply, options.onError);
    }
  };
}

/**
 * Extract API key from request
 */
function extractApiKey(
  request: FastifyRequest,
  headerName: string,
  queryName: string,
  allowQuery: boolean
): string | null {
  // Try header first
  const headerKey = request.headers[headerName.toLowerCase()];
  if (headerKey) {
    return Array.isArray(headerKey) ? headerKey[0] || null : headerKey;
  }

  // Try query parameter if allowed
  if (allowQuery) {
    const query = request.query as Record<string, string | undefined>;
    const queryKey = query[queryName];
    if (queryKey && typeof queryKey === 'string') {
      return queryKey;
    }
  }

  return null;
}

/**
 * Extract client IP address
 */
function extractClientIp(request: FastifyRequest): string {
  return request.ip || request.socket?.remoteAddress || '0.0.0.0';
}

/**
 * Get full request URL
 */
function getFullUrl(request: FastifyRequest): string {
  const protocol = request.protocol || 'http';
  const host = request.hostname || 'localhost';
  const path = request.url || '/';
  return `${protocol}://${host}${path}`;
}

/**
 * Get request body
 */
function getRequestBody(request: FastifyRequest): string | Buffer | undefined {
  const body = request.body;
  if (!body) {
    return undefined;
  }

  if (Buffer.isBuffer(body)) {
    return body;
  }

  if (typeof body === 'string') {
    return body;
  }

  // Serialize object to JSON
  return JSON.stringify(body);
}

/**
 * Extract TOTP token from request
 */
function extractTotpToken(request: FastifyRequest): string | undefined {
  const header = request.headers['x-totp-token'];
  if (header) {
    return Array.isArray(header) ? header[0] : header;
  }
  return undefined;
}

/**
 * Extract signature from request
 */
function extractSignature(request: FastifyRequest): string | undefined {
  const header = request.headers['x-signature'];
  if (header) {
    return Array.isArray(header) ? header[0] : header;
  }
  return undefined;
}

/**
 * Extract HMAC signature from request
 */
function extractHmacSignature(request: FastifyRequest): string | undefined {
  const header = request.headers['x-hmac-signature'];
  if (header) {
    return Array.isArray(header) ? header[0] : header;
  }
  return undefined;
}

/**
 * Extract timestamp from request
 */
function extractTimestamp(request: FastifyRequest): string | number | undefined {
  const header = request.headers['x-timestamp'];
  if (header) {
    const value = Array.isArray(header) ? header[0] : header;
    // Try parsing as number
    const asNumber = parseInt(value || '', 10);
    if (!isNaN(asNumber)) {
      return asNumber;
    }
    return value;
  }
  return undefined;
}

/**
 * Handle authentication error
 */
async function handleError(
  result: ValidationResult,
  request: FastifyRequest,
  reply: FastifyReply,
  customHandler?: (
    error: ValidationResult,
    request: FastifyRequest,
    reply: FastifyReply
  ) => void | Promise<void>
): Promise<void> {
  if (customHandler) {
    await customHandler(result, request, reply);
    return;
  }

  // Default error handler
  reply.status(401).send({
    error: 'Authentication failed',
    message: result.errors[0] || 'Unauthorized',
    details: result.errors,
    correlationId: result.correlationId,
  });
}

// Extend Fastify types for the decorated instance
declare module 'fastify' {
  interface FastifyInstance {
    qiuthAuth: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}
