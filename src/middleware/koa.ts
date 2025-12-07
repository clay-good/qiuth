/**
 * Koa Middleware for Qiuth
 *
 * Provides authentication middleware for Koa applications.
 * Extracts API keys, validates requests, and attaches authentication info to ctx.state.
 *
 * @packageDocumentation
 */

import type { Context, Next, Middleware } from 'koa';
import { QiuthAuthenticator } from '../core/authenticator';
import {
  QiuthConfig,
  AuthenticationRequest,
  ValidationResult,
  AuthenticatorOptions,
} from '../types';

/**
 * Qiuth authentication info attached to Koa context state
 */
export interface QiuthKoaAuth {
  /** Validation result */
  result: ValidationResult;
  /** Validated configuration */
  config: QiuthConfig;
  /** API key used (not hashed) */
  apiKey: string;
}

/**
 * Extended Koa state with Qiuth authentication info
 */
export interface QiuthKoaState {
  qiuth?: QiuthKoaAuth;
}

/**
 * Configuration lookup function
 *
 * This function is called to retrieve the configuration for a given API key.
 * It should return the configuration or null if the key is not found.
 */
export type KoaConfigLookupFunction = (
  apiKey: string
) => Promise<QiuthConfig | null> | QiuthConfig | null;

/**
 * Options for Qiuth Koa middleware
 */
export interface QiuthKoaOptions extends AuthenticatorOptions {
  /**
   * Function to lookup configuration for an API key
   * This is typically a database query
   */
  configLookup: KoaConfigLookupFunction;

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
  onError?: (error: ValidationResult, ctx: Context) => void | Promise<void>;

  /**
   * Custom success handler
   * If not provided, continues to next middleware
   */
  onSuccess?: (result: ValidationResult, ctx: Context) => void | Promise<void>;
}

/**
 * Create Qiuth Koa middleware
 *
 * @param options - Middleware options
 * @returns Koa middleware function
 *
 * @example
 * ```typescript
 * import Koa from 'koa';
 * import { createQiuthKoaMiddleware } from 'qiuth';
 *
 * const app = new Koa();
 *
 * const qiuthMiddleware = createQiuthKoaMiddleware({
 *   configLookup: async (apiKey) => {
 *     return await db.getApiKeyConfig(apiKey);
 *   },
 * });
 *
 * // Apply to all routes
 * app.use(qiuthMiddleware);
 *
 * // Or use with koa-router for specific routes
 * router.get('/protected', qiuthMiddleware, async (ctx) => {
 *   ctx.body = { authenticated: true, apiKey: ctx.state['qiuth']?.apiKey };
 * });
 * ```
 */
export function createQiuthKoaMiddleware(options: QiuthKoaOptions): Middleware {
  const authenticator = new QiuthAuthenticator({
    debug: options.debug,
    logger: options.logger,
    collectMetrics: options.collectMetrics,
  });

  const apiKeyHeader = options.apiKeyHeader ?? 'x-api-key';
  const apiKeyQuery = options.apiKeyQuery ?? 'api_key';
  const allowQueryKey = options.allowQueryKey ?? false;

  return async (ctx: Context, next: Next): Promise<void> => {
    try {
      // Extract API key
      const apiKey = extractApiKey(ctx, apiKeyHeader, apiKeyQuery, allowQueryKey);
      if (!apiKey) {
        const errorResult: ValidationResult = {
          success: false,
          errors: ['API key is required'],
          layerResults: [],
          validatedAt: new Date(),
        };
        await handleError(errorResult, ctx, options.onError);
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
        await handleError(errorResult, ctx, options.onError);
        return;
      }

      // Build authentication request
      const authRequest: AuthenticationRequest = {
        apiKey,
        clientIp: extractClientIp(ctx),
        method: ctx.method,
        url: getFullUrl(ctx),
        body: getRequestBody(ctx),
        headers: ctx.headers as Record<string, string | string[] | undefined>,
        totpToken: extractTotpToken(ctx),
        signature: extractSignature(ctx),
        hmacSignature: extractHmacSignature(ctx),
        timestamp: extractTimestamp(ctx),
      };

      // Authenticate
      const result = await authenticator.authenticate(authRequest, config);

      if (result.success) {
        // Attach authentication info to context state
        ctx.state['qiuth'] = {
          result,
          config,
          apiKey,
        };

        // Call success handler if provided
        if (options.onSuccess) {
          await options.onSuccess(result, ctx);
        }

        // Continue to next middleware
        await next();
      } else {
        await handleError(result, ctx, options.onError);
      }
    } catch (error) {
      const errorResult: ValidationResult = {
        success: false,
        errors: [`Internal error: ${error instanceof Error ? error.message : 'Unknown error'}`],
        layerResults: [],
        validatedAt: new Date(),
      };
      await handleError(errorResult, ctx, options.onError);
    }
  };
}

/**
 * Extract API key from request
 */
function extractApiKey(
  ctx: Context,
  headerName: string,
  queryName: string,
  allowQuery: boolean
): string | null {
  // Try header first
  const headerKey = ctx.get(headerName);
  if (headerKey) {
    return headerKey;
  }

  // Try query parameter if allowed
  if (allowQuery) {
    const queryKey = ctx.query[queryName];
    if (queryKey && typeof queryKey === 'string') {
      return queryKey;
    }
  }

  return null;
}

/**
 * Extract client IP address
 */
function extractClientIp(ctx: Context): string {
  // Koa provides ctx.ip which respects proxy settings
  return ctx.ip || ctx.socket?.remoteAddress || '0.0.0.0';
}

/**
 * Get full request URL
 */
function getFullUrl(ctx: Context): string {
  return ctx.href || `${ctx.protocol}://${ctx.host}${ctx.url}`;
}

/**
 * Get request body
 */
function getRequestBody(ctx: Context): string | Buffer | undefined {
  // Koa requires body-parser middleware to populate ctx.request.body
  const body = (ctx.request as { body?: unknown }).body;
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
function extractTotpToken(ctx: Context): string | undefined {
  const header = ctx.get('x-totp-token');
  return header || undefined;
}

/**
 * Extract signature from request
 */
function extractSignature(ctx: Context): string | undefined {
  const header = ctx.get('x-signature');
  return header || undefined;
}

/**
 * Extract HMAC signature from request
 */
function extractHmacSignature(ctx: Context): string | undefined {
  const header = ctx.get('x-hmac-signature');
  return header || undefined;
}

/**
 * Extract timestamp from request
 */
function extractTimestamp(ctx: Context): string | number | undefined {
  const header = ctx.get('x-timestamp');
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
async function handleError(
  result: ValidationResult,
  ctx: Context,
  customHandler?: (error: ValidationResult, ctx: Context) => void | Promise<void>
): Promise<void> {
  if (customHandler) {
    await customHandler(result, ctx);
    return;
  }

  // Default error handler
  ctx.status = 401;
  ctx.body = {
    error: 'Authentication failed',
    message: result.errors[0] || 'Unauthorized',
    details: result.errors,
    correlationId: result.correlationId,
  };
}
