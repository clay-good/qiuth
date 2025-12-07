/**
 * Hono Middleware for Qiuth
 *
 * Provides authentication middleware for Hono applications.
 * Works with Cloudflare Workers, Deno Deploy, Bun, and Node.js.
 * Extracts API keys, validates requests, and attaches authentication info to context.
 *
 * @packageDocumentation
 */

import type { Context, MiddlewareHandler } from 'hono';
import { QiuthAuthenticator } from '../core/authenticator';
import {
  QiuthConfig,
  AuthenticationRequest,
  ValidationResult,
  AuthenticatorOptions,
} from '../types';

/**
 * Qiuth authentication info attached to Hono context
 */
export interface QiuthHonoAuth {
  /** Validation result */
  result: ValidationResult;
  /** Validated configuration */
  config: QiuthConfig;
  /** API key used (not hashed) */
  apiKey: string;
}

/**
 * Hono context variables for Qiuth
 */
export interface QiuthHonoVariables {
  qiuth: QiuthHonoAuth;
}

/**
 * Configuration lookup function
 *
 * This function is called to retrieve the configuration for a given API key.
 * It should return the configuration or null if the key is not found.
 */
export type HonoConfigLookupFunction = (
  apiKey: string
) => Promise<QiuthConfig | null> | QiuthConfig | null;

/**
 * Options for Qiuth Hono middleware
 */
export interface QiuthHonoOptions extends AuthenticatorOptions {
  /**
   * Function to lookup configuration for an API key
   * This is typically a database query or KV store lookup
   */
  configLookup: HonoConfigLookupFunction;

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
  onError?: (error: ValidationResult, c: Context) => Response | Promise<Response>;

  /**
   * Custom success handler
   * If not provided, continues to next handler
   */
  onSuccess?: (result: ValidationResult, c: Context) => void | Promise<void>;
}

/**
 * Create Qiuth Hono middleware
 *
 * @param options - Middleware options
 * @returns Hono middleware function
 *
 * @example
 * ```typescript
 * import { Hono } from 'hono';
 * import { createQiuthHonoMiddleware } from 'qiuth';
 *
 * const app = new Hono();
 *
 * const qiuthMiddleware = createQiuthHonoMiddleware({
 *   configLookup: async (apiKey) => {
 *     // For Cloudflare Workers, you might use KV
 *     const config = await env.API_KEYS.get(apiKey, 'json');
 *     return config;
 *   },
 * });
 *
 * // Apply to all routes
 * app.use('/api/*', qiuthMiddleware);
 *
 * // Or use for specific routes
 * app.get('/protected', qiuthMiddleware, (c) => {
 *   const auth = c.get('qiuth');
 *   return c.json({ authenticated: true, apiKey: auth?.apiKey });
 * });
 * ```
 *
 * @example Cloudflare Workers
 * ```typescript
 * import { Hono } from 'hono';
 * import { createQiuthHonoMiddleware } from 'qiuth';
 *
 * type Bindings = {
 *   API_KEYS: KVNamespace;
 * };
 *
 * const app = new Hono<{ Bindings: Bindings }>();
 *
 * app.use('/api/*', async (c, next) => {
 *   const qiuthMiddleware = createQiuthHonoMiddleware({
 *     configLookup: async (apiKey) => {
 *       return await c.env.API_KEYS.get(apiKey, 'json');
 *     },
 *   });
 *   return qiuthMiddleware(c, next);
 * });
 * ```
 */
export function createQiuthHonoMiddleware(options: QiuthHonoOptions): MiddlewareHandler {
  const authenticator = new QiuthAuthenticator({
    debug: options.debug,
    logger: options.logger,
    collectMetrics: options.collectMetrics,
  });

  const apiKeyHeader = options.apiKeyHeader ?? 'x-api-key';
  const apiKeyQuery = options.apiKeyQuery ?? 'api_key';
  const allowQueryKey = options.allowQueryKey ?? false;

  return async (c: Context, next) => {
    try {
      // Extract API key
      const apiKey = extractApiKey(c, apiKeyHeader, apiKeyQuery, allowQueryKey);
      if (!apiKey) {
        const errorResult: ValidationResult = {
          success: false,
          errors: ['API key is required'],
          layerResults: [],
          validatedAt: new Date(),
        };
        return handleError(errorResult, c, options.onError);
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
        return handleError(errorResult, c, options.onError);
      }

      // Build authentication request
      const authRequest: AuthenticationRequest = {
        apiKey,
        clientIp: extractClientIp(c),
        method: c.req.method,
        url: c.req.url,
        body: await getRequestBody(c),
        headers: Object.fromEntries(c.req.raw.headers.entries()),
        totpToken: extractTotpToken(c),
        signature: extractSignature(c),
        hmacSignature: extractHmacSignature(c),
        timestamp: extractTimestamp(c),
      };

      // Authenticate
      const result = await authenticator.authenticate(authRequest, config);

      if (result.success) {
        // Attach authentication info to context
        c.set('qiuth', {
          result,
          config,
          apiKey,
        });

        // Call success handler if provided
        if (options.onSuccess) {
          await options.onSuccess(result, c);
        }

        // Continue to next handler
        return await next();
      } else {
        return handleError(result, c, options.onError);
      }
    } catch (error) {
      const errorResult: ValidationResult = {
        success: false,
        errors: [`Internal error: ${error instanceof Error ? error.message : 'Unknown error'}`],
        layerResults: [],
        validatedAt: new Date(),
      };
      return handleError(errorResult, c, options.onError);
    }
  };
}

/**
 * Extract API key from request
 */
function extractApiKey(
  c: Context,
  headerName: string,
  queryName: string,
  allowQuery: boolean
): string | null {
  // Try header first
  const headerKey = c.req.header(headerName);
  if (headerKey) {
    return headerKey;
  }

  // Try query parameter if allowed
  if (allowQuery) {
    const queryKey = c.req.query(queryName);
    if (queryKey) {
      return queryKey;
    }
  }

  return null;
}

/**
 * Extract client IP address
 */
function extractClientIp(c: Context): string {
  // Try common headers for proxied requests
  const cfConnectingIp = c.req.header('cf-connecting-ip');
  if (cfConnectingIp) {
    return cfConnectingIp;
  }

  const xForwardedFor = c.req.header('x-forwarded-for');
  if (xForwardedFor) {
    // Take the first IP in the chain
    return xForwardedFor.split(',')[0]?.trim() || '0.0.0.0';
  }

  const xRealIp = c.req.header('x-real-ip');
  if (xRealIp) {
    return xRealIp;
  }

  // Fallback - in edge environments, there may not be a direct socket
  return '0.0.0.0';
}

/**
 * Get request body
 */
async function getRequestBody(c: Context): Promise<string | undefined> {
  // Only read body for methods that typically have one
  const method = c.req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return undefined;
  }

  try {
    // Try to get body as text
    const body = await c.req.text();
    return body || undefined;
  } catch {
    // Body may have already been consumed or not available
    return undefined;
  }
}

/**
 * Extract TOTP token from request
 */
function extractTotpToken(c: Context): string | undefined {
  return c.req.header('x-totp-token') || undefined;
}

/**
 * Extract signature from request
 */
function extractSignature(c: Context): string | undefined {
  return c.req.header('x-signature') || undefined;
}

/**
 * Extract HMAC signature from request
 */
function extractHmacSignature(c: Context): string | undefined {
  return c.req.header('x-hmac-signature') || undefined;
}

/**
 * Extract timestamp from request
 */
function extractTimestamp(c: Context): string | number | undefined {
  const header = c.req.header('x-timestamp');
  if (header) {
    // Try parsing as number
    const asNumber = parseInt(header, 10);
    if (!isNaN(asNumber)) {
      return asNumber;
    }
    return header;
  }
  return undefined;
}

/**
 * Handle authentication error
 */
function handleError(
  result: ValidationResult,
  c: Context,
  customHandler?: (error: ValidationResult, c: Context) => Response | Promise<Response>
): Response | Promise<Response> {
  if (customHandler) {
    return customHandler(result, c);
  }

  // Default error handler
  return c.json(
    {
      error: 'Authentication failed',
      message: result.errors[0] || 'Unauthorized',
      details: result.errors,
      correlationId: result.correlationId,
    },
    401
  );
}
