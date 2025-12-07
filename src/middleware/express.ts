/**
 * Express Middleware for Qiuth
 *
 * Provides drop-in authentication middleware for Express applications.
 * Extracts API keys, validates requests, and attaches authentication info to req.
 *
 * @packageDocumentation
 */

import { Request, Response, NextFunction } from 'express';
import { QiuthAuthenticator } from '../core/authenticator';
import {
  QiuthConfig,
  AuthenticationRequest,
  ValidationResult,
  AuthenticatorOptions,
} from '../types';

/**
 * Extended Express Request with Qiuth authentication info
 */
export interface QiuthRequest extends Request {
  /**
   * Qiuth authentication result
   * Only present if authentication succeeded
   */
  qiuth?: {
    /** Validation result */
    result: ValidationResult;
    /** Validated configuration */
    config: QiuthConfig;
    /** API key used (not hashed) */
    apiKey: string;
  };
}

/**
 * Configuration lookup function
 *
 * This function is called to retrieve the configuration for a given API key.
 * It should return the configuration or null if the key is not found.
 */
export type ConfigLookupFunction = (
  apiKey: string
) => Promise<QiuthConfig | null> | QiuthConfig | null;

/**
 * Options for Qiuth Express middleware
 */
export interface QiuthMiddlewareOptions extends AuthenticatorOptions {
  /**
   * Function to lookup configuration for an API key
   * This is typically a database query
   */
  configLookup: ConfigLookupFunction;

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
  onError?: (error: ValidationResult, req: Request, res: Response) => void;

  /**
   * Custom success handler
   * If not provided, calls next()
   */
  onSuccess?: (
    result: ValidationResult,
    req: QiuthRequest,
    res: Response,
    next: NextFunction
  ) => void;
}

/**
 * Create Qiuth Express middleware
 *
 * @param options - Middleware options
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * const qiuthMiddleware = createQiuthMiddleware({
 *   configLookup: async (apiKey) => {
 *     return await db.getApiKeyConfig(apiKey);
 *   },
 * });
 *
 * app.use('/api', qiuthMiddleware);
 * ```
 */
export function createQiuthMiddleware(options: QiuthMiddlewareOptions) {
  const authenticator = new QiuthAuthenticator({
    debug: options.debug,
    logger: options.logger,
    collectMetrics: options.collectMetrics,
  });

  const apiKeyHeader = options.apiKeyHeader ?? 'x-api-key';
  const apiKeyQuery = options.apiKeyQuery ?? 'api_key';
  const allowQueryKey = options.allowQueryKey ?? false;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Extract API key
      const apiKey = extractApiKey(req, apiKeyHeader, apiKeyQuery, allowQueryKey);
      if (!apiKey) {
        handleError(
          {
            success: false,
            errors: ['API key is required'],
            layerResults: [],
            validatedAt: new Date(),
          },
          req,
          res,
          options.onError
        );
        return;
      }

      // Lookup configuration
      const config = await options.configLookup(apiKey);
      if (!config) {
        handleError(
          {
            success: false,
            errors: ['Invalid API key'],
            layerResults: [],
            validatedAt: new Date(),
          },
          req,
          res,
          options.onError
        );
        return;
      }

      // Build authentication request
      const authRequest: AuthenticationRequest = {
        apiKey,
        clientIp: extractClientIp(req),
        method: req.method,
        url: getFullUrl(req),
        body: getRequestBody(req),
        headers: req.headers as Record<string, string | string[] | undefined>,
        totpToken: extractTotpToken(req),
        signature: extractSignature(req),
        hmacSignature: extractHmacSignature(req),
        timestamp: extractTimestamp(req),
      };

      // Authenticate
      const result = await authenticator.authenticate(authRequest, config);

      if (result.success) {
        // Attach authentication info to request
        (req as QiuthRequest).qiuth = {
          result,
          config,
          apiKey,
        };

        // Call success handler or next
        if (options.onSuccess) {
          options.onSuccess(result, req as QiuthRequest, res, next);
        } else {
          next();
        }
      } else {
        handleError(result, req, res, options.onError);
      }
    } catch (error) {
      handleError(
        {
          success: false,
          errors: [`Internal error: ${error instanceof Error ? error.message : 'Unknown error'}`],
          layerResults: [],
          validatedAt: new Date(),
        },
        req,
        res,
        options.onError
      );
    }
  };
}

/**
 * Extract API key from request
 */
function extractApiKey(
  req: Request,
  headerName: string,
  queryName: string,
  allowQuery: boolean
): string | null {
  // Try header first
  const headerKey = req.headers[headerName.toLowerCase()];
  if (headerKey) {
    return Array.isArray(headerKey) ? headerKey[0] || null : headerKey;
  }

  // Try query parameter if allowed
  if (allowQuery) {
    const queryKey = req.query[queryName];
    if (queryKey && typeof queryKey === 'string') {
      return queryKey;
    }
  }

  return null;
}

/**
 * Extract client IP address
 */
function extractClientIp(req: Request): string {
  // Express provides this through req.ip
  return req.ip || req.socket.remoteAddress || '0.0.0.0';
}

/**
 * Get full request URL
 */
function getFullUrl(req: Request): string {
  const protocol = req.protocol;
  const host = req.get('host') || 'localhost';
  const path = req.originalUrl || req.url;
  return `${protocol}://${host}${path}`;
}

/**
 * Get request body
 */
function getRequestBody(req: Request): string | Buffer | undefined {
  if (!req.body) {
    return undefined;
  }

  if (Buffer.isBuffer(req.body)) {
    return req.body;
  }

  if (typeof req.body === 'string') {
    return req.body;
  }

  // Serialize object to JSON
  return JSON.stringify(req.body);
}

/**
 * Extract TOTP token from request
 */
function extractTotpToken(req: Request): string | undefined {
  const header = req.headers['x-totp-token'];
  if (header) {
    return Array.isArray(header) ? header[0] : header;
  }
  return undefined;
}

/**
 * Extract signature from request
 */
function extractSignature(req: Request): string | undefined {
  const header = req.headers['x-signature'];
  if (header) {
    return Array.isArray(header) ? header[0] : header;
  }
  return undefined;
}

/**
 * Extract HMAC signature from request
 */
function extractHmacSignature(req: Request): string | undefined {
  const header = req.headers['x-hmac-signature'];
  if (header) {
    return Array.isArray(header) ? header[0] : header;
  }
  return undefined;
}

/**
 * Extract timestamp from request
 */
function extractTimestamp(req: Request): string | number | undefined {
  const header = req.headers['x-timestamp'];
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
function handleError(
  result: ValidationResult,
  req: Request,
  res: Response,
  customHandler?: (error: ValidationResult, req: Request, res: Response) => void
): void {
  if (customHandler) {
    customHandler(result, req, res);
    return;
  }

  // Default error handler
  res.status(401).json({
    error: 'Authentication failed',
    message: result.errors[0] || 'Unauthorized',
    details: result.errors,
    correlationId: result.correlationId,
  });
}
