/**
 * Qiuth Client Library
 *
 * Provides a client-side helper for making authenticated requests.
 * Automatically handles TOTP generation, request signing, and header management.
 *
 * @packageDocumentation
 */

import { TotpValidator } from '../validators/totp-validator';
import { CertificateValidator } from '../validators/certificate-validator';
import { HmacValidator } from '../validators/hmac-validator';

/**
 * Options for QiuthClient
 */
export interface QiuthClientOptions {
  /**
   * API key for authentication
   */
  apiKey: string;

  /**
   * Base URL for API requests
   * @example 'https://api.example.com'
   */
  baseUrl: string;

  /**
   * TOTP secret (if TOTP MFA is enabled)
   * Base32-encoded secret
   */
  totpSecret?: string;

  /**
   * Private key for request signing (if certificate auth is enabled)
   * PEM-encoded RSA private key
   */
  privateKey?: string;

  /**
   * HMAC shared secret (if HMAC auth is enabled)
   * Must be at least 32 characters
   */
  hmacSecret?: string;

  /**
   * Custom headers to include in all requests
   */
  headers?: Record<string, string>;

  /**
   * Request timeout in milliseconds
   * @default 30000 (30 seconds)
   */
  timeout?: number;

  /**
   * Number of retry attempts for failed requests
   * @default 3
   */
  retries?: number;

  /**
   * Delay between retries in milliseconds
   * @default 1000
   */
  retryDelay?: number;
}

/**
 * Request options for individual requests
 */
export interface RequestOptions {
  /**
   * Request headers
   */
  headers?: Record<string, string>;

  /**
   * Request body
   */
  body?: unknown;

  /**
   * Query parameters
   */
  params?: Record<string, string>;

  /**
   * Request timeout (overrides client default)
   */
  timeout?: number;
}

/**
 * Response from Qiuth client
 */
export interface QiuthResponse<T = unknown> {
  /**
   * Response data
   */
  data: T;

  /**
   * HTTP status code
   */
  status: number;

  /**
   * Response headers
   */
  headers: Record<string, string>;
}

/**
 * Qiuth HTTP client
 *
 * Provides convenient methods for making authenticated API requests.
 * Automatically handles TOTP token generation and request signing.
 *
 * @example
 * ```typescript
 * const client = new QiuthClient({
 *   apiKey: 'your-api-key',
 *   baseUrl: 'https://api.example.com',
 *   totpSecret: 'BASE32_SECRET',
 *   privateKey: '-----BEGIN PRIVATE KEY-----...',
 * });
 *
 * const response = await client.get('/users');
 * console.log(response.data);
 * ```
 */
export class QiuthClient {
  private readonly options: Required<Omit<QiuthClientOptions, 'totpSecret' | 'privateKey' | 'hmacSecret'>> & {
    totpSecret?: string;
    privateKey?: string;
    hmacSecret?: string;
  };
  private totpValidator?: TotpValidator;

  /**
   * Create a new Qiuth client
   * @param options - Client options
   */
  constructor(options: QiuthClientOptions) {
    this.options = {
      apiKey: options.apiKey,
      baseUrl: options.baseUrl.replace(/\/$/, ''), // Remove trailing slash
      totpSecret: options.totpSecret,
      privateKey: options.privateKey,
      hmacSecret: options.hmacSecret,
      headers: options.headers || {},
      timeout: options.timeout ?? 30000,
      retries: options.retries ?? 3,
      retryDelay: options.retryDelay ?? 1000,
    };

    // Initialize TOTP validator if secret is provided
    if (this.options.totpSecret) {
      this.totpValidator = new TotpValidator({
        enabled: true,
        secret: this.options.totpSecret,
      });
    }
  }

  /**
   * Make a GET request
   */
  public async get<T = unknown>(path: string, options?: RequestOptions): Promise<QiuthResponse<T>> {
    return this.request<T>('GET', path, options);
  }

  /**
   * Make a POST request
   */
  public async post<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<QiuthResponse<T>> {
    return this.request<T>('POST', path, { ...options, body });
  }

  /**
   * Make a PUT request
   */
  public async put<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<QiuthResponse<T>> {
    return this.request<T>('PUT', path, { ...options, body });
  }

  /**
   * Make a PATCH request
   */
  public async patch<T = unknown>(
    path: string,
    body?: unknown,
    options?: RequestOptions
  ): Promise<QiuthResponse<T>> {
    return this.request<T>('PATCH', path, { ...options, body });
  }

  /**
   * Make a DELETE request
   */
  public async delete<T = unknown>(
    path: string,
    options?: RequestOptions
  ): Promise<QiuthResponse<T>> {
    return this.request<T>('DELETE', path, options);
  }

  /**
   * Make an HTTP request with authentication
   */
  private async request<T>(
    method: string,
    path: string,
    options: RequestOptions = {}
  ): Promise<QiuthResponse<T>> {
    const url = this.buildUrl(path, options.params);
    const headers = this.buildHeaders(method, url, options);
    const body = this.serializeBody(options.body);

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.options.retries; attempt++) {
      try {
        const response = await this.executeRequest<T>(method, url, headers, body, options.timeout);
        return response;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');

        // Don't retry on client errors (4xx)
        if (error instanceof Error && 'status' in error) {
          const status = (error as { status: number }).status;
          if (status >= 400 && status < 500) {
            throw error;
          }
        }

        // Wait before retrying
        if (attempt < this.options.retries) {
          await this.sleep(this.options.retryDelay * (attempt + 1));
        }
      }
    }

    throw lastError || new Error('Request failed after retries');
  }

  /**
   * Build full URL with query parameters
   */
  private buildUrl(path: string, params?: Record<string, string>): string {
    const fullPath = path.startsWith('/') ? path : `/${path}`;
    let url = `${this.options.baseUrl}${fullPath}`;

    if (params && Object.keys(params).length > 0) {
      const queryString = new URLSearchParams(params).toString();
      url += `?${queryString}`;
    }

    return url;
  }

  /**
   * Build request headers with authentication
   */
  private buildHeaders(
    method: string,
    url: string,
    options: RequestOptions
  ): Record<string, string> {
    const headers: Record<string, string> = {
      ...this.options.headers,
      ...options.headers,
      'x-api-key': this.options.apiKey,
    };

    // Add TOTP token if available
    if (this.totpValidator) {
      headers['x-totp-token'] = this.totpValidator.generate();
    }

    // Add signature if private key is available (certificate auth)
    if (this.options.privateKey) {
      const timestamp = Date.now();
      const body = this.serializeBody(options.body);
      const signature = CertificateValidator.sign(
        this.options.privateKey,
        method,
        url,
        body,
        timestamp
      );
      headers['x-signature'] = signature;
      headers['x-timestamp'] = timestamp.toString();
    }

    // Add HMAC signature if HMAC secret is available
    if (this.options.hmacSecret) {
      const timestamp = Date.now();
      const body = this.serializeBody(options.body);
      const hmacSignature = HmacValidator.sign(
        this.options.hmacSecret,
        method,
        url,
        body,
        timestamp
      );
      headers['x-hmac-signature'] = hmacSignature;
      // Only set timestamp if not already set by certificate auth
      if (!headers['x-timestamp']) {
        headers['x-timestamp'] = timestamp.toString();
      }
    }

    // Add content-type for requests with body
    if (options.body && !headers['content-type']) {
      headers['content-type'] = 'application/json';
    }

    return headers;
  }

  /**
   * Serialize request body
   */
  private serializeBody(body: unknown): string | undefined {
    if (!body) {
      return undefined;
    }

    if (typeof body === 'string') {
      return body;
    }

    return JSON.stringify(body);
  }

  /**
   * Execute HTTP request using fetch
   */
  private async executeRequest<T>(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: string | undefined,
    timeout?: number
  ): Promise<QiuthResponse<T>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout ?? this.options.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      let data: T;
      const contentType = response.headers.get('content-type');
      if (contentType?.includes('application/json')) {
        data = (await response.json()) as T;
      } else {
        data = (await response.text()) as T;
      }

      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}: ${response.statusText}`) as Error & {
          status: number;
          data: T;
        };
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return {
        data,
        status: response.status,
        headers: responseHeaders,
      };
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * Sleep for a specified duration
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
