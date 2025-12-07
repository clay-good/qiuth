/**
 * HMAC-Based Authentication Module
 *
 * Provides request signing and verification using HMAC-SHA256.
 * A lighter-weight alternative to certificate-based authentication
 * that still provides proof-of-possession through shared secrets.
 *
 * @packageDocumentation
 */

import { HmacConfig } from '../types';
import { createHmac, createHash, timingSafeEqual } from 'node:crypto';

/**
 * Validator for HMAC-based authentication layer
 *
 * HMAC (Hash-based Message Authentication Code) provides:
 * - Request integrity verification (tampering detection)
 * - Proof of shared secret possession
 * - Replay attack prevention via timestamp validation
 *
 * Use HMAC when:
 * - You need lighter-weight authentication than RSA certificates
 * - Both client and server can securely store a shared secret
 * - You're securing internal service-to-service communication
 *
 * Use certificates instead when:
 * - Clients are external/untrusted
 * - You need non-repudiation
 * - Key distribution is a concern
 */
export class HmacValidator {
  private readonly maxAge: number;
  private readonly maxAgeMs: number;
  private readonly secretBuffer: Buffer;

  /**
   * Create a new HMAC validator
   * @param config - HMAC configuration
   */
  constructor(config: HmacConfig) {
    if (!config.enabled) {
      throw new Error('HMAC authentication is not enabled in configuration');
    }
    if (!config.secret) {
      throw new Error('Shared secret is required when HMAC authentication is enabled');
    }
    if (config.secret.length < 32) {
      throw new Error('HMAC secret must be at least 32 characters for security');
    }

    this.maxAge = config.maxAge ?? 300; // Default 5 minutes
    this.maxAgeMs = this.maxAge * 1000; // Pre-calculate for performance

    if (this.maxAge <= 0) {
      throw new Error('HMAC maxAge must be positive');
    }

    // Pre-convert secret to buffer for faster HMAC operations
    this.secretBuffer = Buffer.from(config.secret);
  }

  /**
   * Verify a signed request
   *
   * Validates that:
   * 1. The HMAC signature is valid for the request
   * 2. The timestamp is within acceptable range (not too old, not in future)
   * 3. The request hasn't been tampered with
   *
   * @param signature - Hex-encoded HMAC signature
   * @param method - HTTP method (GET, POST, etc.)
   * @param url - Full request URL
   * @param body - Request body (if any)
   * @param timestamp - Request timestamp (ISO 8601 or Unix timestamp in ms)
   * @returns true if signature is valid and request is fresh
   */
  public verify(
    signature: string,
    method: string,
    url: string,
    body?: string | Buffer,
    timestamp?: string | number
  ): boolean {
    // Fast-fail on empty inputs
    if (!signature || !timestamp || !method || !url) {
      return false;
    }

    // Validate timestamp first (cheapest check)
    const timestampMs = this.parseTimestamp(timestamp);
    if (!this.isTimestampValid(timestampMs)) {
      return false;
    }

    // Validate signature format (should be hex)
    if (!/^[a-f0-9]{64}$/i.test(signature)) {
      return false;
    }

    // Create canonical request representation
    const canonical = this.createCanonicalRequest(method, url, body, timestampMs);

    // Compute expected signature
    const expectedSignature = this.computeHmac(canonical);

    // Constant-time comparison to prevent timing attacks
    try {
      const signatureBuffer = Buffer.from(signature, 'hex');
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');
      return timingSafeEqual(signatureBuffer, expectedBuffer);
    } catch {
      return false;
    }
  }

  /**
   * Sign a request (used by clients)
   *
   * Creates an HMAC signature that proves possession of the shared secret
   * without revealing the secret itself.
   *
   * @param secret - Shared secret
   * @param method - HTTP method
   * @param url - Full request URL
   * @param body - Request body (if any)
   * @param timestamp - Request timestamp (defaults to current time)
   * @returns Hex-encoded HMAC signature
   */
  public static sign(
    secret: string,
    method: string,
    url: string,
    body?: string | Buffer,
    timestamp?: number
  ): string {
    const timestampMs = timestamp ?? Date.now();
    const canonical = HmacValidator.createCanonicalRequestStatic(
      method,
      url,
      body,
      timestampMs
    );

    const hmac = createHmac('sha256', secret);
    hmac.update(canonical);
    return hmac.digest('hex');
  }

  /**
   * Generate a cryptographically secure HMAC secret
   *
   * @param length - Length in bytes (default 32 = 256 bits)
   * @returns Hex-encoded secret
   */
  public static generateSecret(length: number = 32): string {
    const { randomBytes } = require('node:crypto');
    return randomBytes(length).toString('hex');
  }

  /**
   * Compute HMAC for a canonical request
   *
   * @param canonical - Canonical request string
   * @returns Hex-encoded HMAC
   */
  private computeHmac(canonical: string): string {
    const hmac = createHmac('sha256', this.secretBuffer);
    hmac.update(canonical);
    return hmac.digest('hex');
  }

  /**
   * Parse timestamp from various formats
   *
   * Accepts:
   * - Unix timestamp in milliseconds (number)
   * - Unix timestamp in milliseconds (string)
   * - ISO 8601 date string
   *
   * @param timestamp - Timestamp in various formats
   * @returns Unix timestamp in milliseconds
   */
  private parseTimestamp(timestamp: string | number): number {
    if (typeof timestamp === 'number') {
      return timestamp;
    }

    // Try parsing as ISO 8601 first (contains non-digit characters)
    if (/[^\d]/.test(timestamp)) {
      const asDate = new Date(timestamp);
      if (!isNaN(asDate.getTime())) {
        return asDate.getTime();
      }
      return NaN;
    }

    // Parse as number
    const asNumber = parseInt(timestamp, 10);
    if (!isNaN(asNumber)) {
      return asNumber;
    }

    return NaN;
  }

  /**
   * Check if timestamp is within acceptable range
   *
   * Rejects timestamps that are:
   * - Too old (older than maxAge)
   * - In the future (with small tolerance for clock skew)
   *
   * @param timestampMs - Timestamp in milliseconds
   * @returns true if timestamp is valid
   */
  private isTimestampValid(timestampMs: number): boolean {
    if (isNaN(timestampMs) || timestampMs <= 0) {
      return false;
    }

    const now = Date.now();
    const age = now - timestampMs;

    // Reject if too old (using pre-calculated maxAgeMs)
    if (age > this.maxAgeMs) {
      return false;
    }

    // Reject if in the future (with 60 second tolerance for clock skew)
    if (age < -60000) {
      return false;
    }

    return true;
  }

  /**
   * Create canonical representation of a request
   *
   * This ensures that the same request always produces the same signature,
   * regardless of how it's formatted.
   *
   * Format:
   * METHOD\n
   * URL\n
   * TIMESTAMP\n
   * BODY_HASH
   *
   * @param method - HTTP method
   * @param url - Full request URL
   * @param body - Request body
   * @param timestampMs - Timestamp in milliseconds
   * @returns Canonical request string
   */
  private createCanonicalRequest(
    method: string,
    url: string,
    body: string | Buffer | undefined,
    timestampMs: number
  ): string {
    return HmacValidator.createCanonicalRequestStatic(method, url, body, timestampMs);
  }

  /**
   * Static version of createCanonicalRequest for use in signing
   */
  private static createCanonicalRequestStatic(
    method: string,
    url: string,
    body: string | Buffer | undefined,
    timestampMs: number
  ): string {
    // Normalize method to uppercase
    const normalizedMethod = method.toUpperCase();

    // Normalize URL (remove fragment, preserve query string)
    const normalizedUrl = url.split('#')[0] || url;

    // Hash body if present
    const bodyHash = body ? this.hashBody(body) : '';

    // Create canonical string
    return `${normalizedMethod}\n${normalizedUrl}\n${timestampMs}\n${bodyHash}`;
  }

  /**
   * Hash request body for inclusion in signature
   *
   * Uses SHA-256 to create a fixed-size representation of the body.
   *
   * @param body - Request body
   * @returns Hex-encoded SHA-256 hash
   */
  private static hashBody(body: string | Buffer): string {
    const hash = createHash('sha256');
    hash.update(body);
    return hash.digest('hex');
  }

  /**
   * Get the maximum age for signed requests
   *
   * @returns Maximum age in seconds
   */
  public getMaxAge(): number {
    return this.maxAge;
  }

  /**
   * Check if a timestamp would be considered valid
   *
   * Useful for testing and debugging.
   *
   * @param timestamp - Timestamp to check
   * @returns true if timestamp is valid
   */
  public isTimestampAcceptable(timestamp: string | number): boolean {
    const timestampMs = this.parseTimestamp(timestamp);
    return this.isTimestampValid(timestampMs);
  }
}
