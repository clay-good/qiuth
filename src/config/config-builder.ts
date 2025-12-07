/**
 * Configuration Builder
 *
 * Provides a fluent API for building Qiuth configurations.
 * Makes it easy to configure security layers with sensible defaults.
 *
 * @packageDocumentation
 */

import { QiuthConfig, IpAllowlistConfig, TotpConfig, CertificateConfig, HmacConfig } from '../types';
import { QiuthAuthenticator } from '../core/authenticator';

/**
 * Fluent configuration builder for Qiuth
 *
 * @example
 * ```typescript
 * const config = new QiuthConfigBuilder()
 *   .withApiKey('my-api-key')
 *   .withIpAllowlist(['192.168.1.0/24', '10.0.0.1'])
 *   .withTotp('BASE32_SECRET')
 *   .build();
 * ```
 */
export class QiuthConfigBuilder {
  private config: Partial<QiuthConfig> = {};

  /**
   * Set the API key (will be hashed automatically)
   * @param apiKey - Plain text API key
   */
  public withApiKey(apiKey: string): this {
    this.config.hashedApiKey = QiuthAuthenticator.hashApiKey(apiKey);
    return this;
  }

  /**
   * Set the hashed API key directly
   * @param hashedApiKey - Pre-hashed API key
   */
  public withHashedApiKey(hashedApiKey: string): this {
    this.config.hashedApiKey = hashedApiKey;
    return this;
  }

  /**
   * Enable IP allowlist with specified IPs
   * @param allowedIps - Array of IP addresses or CIDR ranges
   * @param trustProxy - Whether to trust X-Forwarded-For header
   */
  public withIpAllowlist(allowedIps: string[], trustProxy = false): this {
    this.config.ipAllowlist = {
      enabled: true,
      allowedIps,
      trustProxy,
    };
    return this;
  }

  /**
   * Configure IP allowlist with full options
   * @param config - IP allowlist configuration
   */
  public withIpAllowlistConfig(config: IpAllowlistConfig): this {
    this.config.ipAllowlist = config;
    return this;
  }

  /**
   * Enable TOTP MFA with specified secret
   * @param secret - Base32-encoded TOTP secret
   * @param timeStep - Time step in seconds (default: 30)
   * @param window - Number of time steps to check (default: 1)
   */
  public withTotp(secret: string, timeStep = 30, window = 1): this {
    this.config.totp = {
      enabled: true,
      secret,
      timeStep,
      window,
    };
    return this;
  }

  /**
   * Configure TOTP with full options
   * @param config - TOTP configuration
   */
  public withTotpConfig(config: TotpConfig): this {
    this.config.totp = config;
    return this;
  }

  /**
   * Enable certificate-based authentication with public key
   * @param publicKey - PEM-encoded RSA public key
   * @param maxAge - Maximum age of request in seconds (default: 300)
   */
  public withCertificate(publicKey: string, maxAge = 300): this {
    this.config.certificate = {
      enabled: true,
      publicKey,
      maxAge,
    };
    return this;
  }

  /**
   * Configure certificate with full options
   * @param config - Certificate configuration
   */
  public withCertificateConfig(config: CertificateConfig): this {
    this.config.certificate = config;
    return this;
  }

  /**
   * Enable HMAC-based authentication with shared secret
   *
   * HMAC provides a lighter-weight alternative to certificate authentication.
   * Use for internal service-to-service communication where both sides
   * can securely store a shared secret.
   *
   * @param secret - Shared secret (minimum 32 characters)
   * @param maxAge - Maximum age of request in seconds (default: 300)
   */
  public withHmac(secret: string, maxAge = 300): this {
    this.config.hmac = {
      enabled: true,
      secret,
      maxAge,
    };
    return this;
  }

  /**
   * Configure HMAC with full options
   * @param config - HMAC configuration
   */
  public withHmacConfig(config: HmacConfig): this {
    this.config.hmac = config;
    return this;
  }

  /**
   * Disable IP allowlist
   */
  public withoutIpAllowlist(): this {
    if (this.config.ipAllowlist) {
      this.config.ipAllowlist.enabled = false;
    }
    return this;
  }

  /**
   * Disable TOTP MFA
   */
  public withoutTotp(): this {
    if (this.config.totp) {
      this.config.totp.enabled = false;
    }
    return this;
  }

  /**
   * Disable certificate authentication
   */
  public withoutCertificate(): this {
    if (this.config.certificate) {
      this.config.certificate.enabled = false;
    }
    return this;
  }

  /**
   * Disable HMAC authentication
   */
  public withoutHmac(): this {
    if (this.config.hmac) {
      this.config.hmac.enabled = false;
    }
    return this;
  }

  /**
   * Build the configuration
   * @throws Error if required fields are missing
   */
  public build(): QiuthConfig {
    if (!this.config.hashedApiKey) {
      throw new Error('API key is required. Use withApiKey() or withHashedApiKey()');
    }

    return {
      hashedApiKey: this.config.hashedApiKey,
      ipAllowlist: this.config.ipAllowlist,
      totp: this.config.totp,
      certificate: this.config.certificate,
      hmac: this.config.hmac,
    };
  }

  /**
   * Create a new builder from existing configuration
   * @param config - Existing configuration
   */
  public static from(config: QiuthConfig): QiuthConfigBuilder {
    const builder = new QiuthConfigBuilder();
    builder.config = { ...config };
    return builder;
  }

  /**
   * Validate a configuration
   * @param config - Configuration to validate
   * @throws Error if configuration is invalid
   */
  public static validate(config: QiuthConfig): void {
    if (!config.hashedApiKey) {
      throw new Error('hashedApiKey is required');
    }

    if (config.ipAllowlist?.enabled) {
      if (!config.ipAllowlist.allowedIps || config.ipAllowlist.allowedIps.length === 0) {
        throw new Error(
          'allowedIps must contain at least one IP address when IP allowlist is enabled'
        );
      }
    }

    if (config.totp?.enabled) {
      if (!config.totp.secret) {
        throw new Error('secret is required when TOTP is enabled');
      }
      if (config.totp.timeStep && config.totp.timeStep <= 0) {
        throw new Error('timeStep must be positive');
      }
      if (config.totp.window !== undefined && config.totp.window < 0) {
        throw new Error('window must be non-negative');
      }
    }

    if (config.certificate?.enabled) {
      if (!config.certificate.publicKey) {
        throw new Error('publicKey is required when certificate authentication is enabled');
      }
      if (config.certificate.maxAge !== undefined && config.certificate.maxAge <= 0) {
        throw new Error('maxAge must be positive');
      }
    }

    if (config.hmac?.enabled) {
      if (!config.hmac.secret) {
        throw new Error('secret is required when HMAC authentication is enabled');
      }
      if (config.hmac.secret.length < 32) {
        throw new Error('HMAC secret must be at least 32 characters for security');
      }
      if (config.hmac.maxAge !== undefined && config.hmac.maxAge <= 0) {
        throw new Error('maxAge must be positive');
      }
    }
  }
}

/**
 * Create a new configuration builder
 *
 * @example
 * ```typescript
 * const config = createConfig()
 *   .withApiKey('my-api-key')
 *   .withIpAllowlist(['192.168.1.0/24'])
 *   .build();
 * ```
 */
export function createConfig(): QiuthConfigBuilder {
  return new QiuthConfigBuilder();
}
