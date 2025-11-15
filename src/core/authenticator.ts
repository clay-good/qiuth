/**
 * Core Authentication Orchestration
 *
 * Coordinates all security validators in a pipeline approach.
 * Implements defense-in-depth by running enabled validators sequentially.
 *
 * @packageDocumentation
 */

import {
  QiuthConfig,
  AuthenticationRequest,
  ValidationResult,
  LayerValidationResult,
  SecurityLayer,
  ValidationErrorType,
  AuthenticatorOptions,
} from '../types';
import { IpValidator } from '../validators/ip-validator';
import { TotpValidator } from '../validators/totp-validator';
import { CertificateValidator } from '../validators/certificate-validator';
import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Core authenticator that orchestrates all security layers
 *
 * This class coordinates the validation pipeline, running each enabled
 * security layer in sequence and aggregating results.
 */
export class QiuthAuthenticator {
  private readonly options: AuthenticatorOptions;

  /**
   * Create a new authenticator
   * @param options - Authenticator options
   */
  constructor(options: AuthenticatorOptions = {}) {
    this.options = {
      debug: options.debug ?? false,
      logger: options.logger ?? console.log,
      collectMetrics: options.collectMetrics ?? true,
    };
  }

  /**
   * Authenticate a request against a configuration
   *
   * Runs all enabled security layers in sequence:
   * 1. IP Allowlist (if enabled)
   * 2. TOTP MFA (if enabled)
   * 3. Certificate Authentication (if enabled)
   *
   * Uses fail-fast approach - stops at first failure.
   *
   * @param request - Authentication request to validate
   * @param config - Configuration to validate against
   * @returns Validation result with detailed layer information
   */
  public async authenticate(
    request: AuthenticationRequest,
    config: QiuthConfig
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const correlationId = this.generateCorrelationId();
    const layerResults: LayerValidationResult[] = [];
    const errors: string[] = [];

    this.log(`[${correlationId}] Starting authentication`, { request, config });

    // Validate API key first
    if (!this.validateApiKey(request.apiKey, config.hashedApiKey)) {
      const error = 'Invalid API key';
      errors.push(error);
      this.log(`[${correlationId}] ${error}`);

      return {
        success: false,
        errors,
        layerResults,
        validatedAt: new Date(),
        validationTimeMs: Date.now() - startTime,
        correlationId,
      };
    }

    // Run IP allowlist validation
    if (config.ipAllowlist?.enabled) {
      const result = this.validateIpAllowlist(request, config, correlationId);
      layerResults.push(result);
      if (!result.passed) {
        errors.push(result.error!);
        return this.createResult(false, errors, layerResults, startTime, correlationId);
      }
    }

    // Run TOTP validation
    if (config.totp?.enabled) {
      const result = this.validateTotp(request, config, correlationId);
      layerResults.push(result);
      if (!result.passed) {
        errors.push(result.error!);
        return this.createResult(false, errors, layerResults, startTime, correlationId);
      }
    }

    // Run certificate validation
    if (config.certificate?.enabled) {
      const result = this.validateCertificate(request, config, correlationId);
      layerResults.push(result);
      if (!result.passed) {
        errors.push(result.error!);
        return this.createResult(false, errors, layerResults, startTime, correlationId);
      }
    }

    // All validations passed
    this.log(`[${correlationId}] Authentication successful`);
    return this.createResult(true, errors, layerResults, startTime, correlationId, config);
  }

  /**
   * Validate API key against stored hash using constant-time comparison
   */
  private validateApiKey(apiKey: string, hashedApiKey: string): boolean {
    if (!apiKey) {
      return false;
    }

    // Hash the provided API key
    const hash = this.hashApiKey(apiKey);

    // Use constant-time comparison to prevent timing attacks
    try {
      return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(hashedApiKey, 'hex'));
    } catch {
      // If lengths don't match, timingSafeEqual throws
      return false;
    }
  }

  /**
   * Hash an API key for secure storage
   *
   * Uses SHA-256 for hashing. In production, consider using a more
   * secure algorithm like bcrypt or Argon2.
   */
  private hashApiKey(apiKey: string): string {
    const hash = createHash('sha256');
    hash.update(apiKey);
    return hash.digest('hex');
  }

  /**
   * Validate IP allowlist layer
   */
  private validateIpAllowlist(
    request: AuthenticationRequest,
    config: QiuthConfig,
    correlationId: string
  ): LayerValidationResult {
    this.log(`[${correlationId}] Validating IP allowlist`);

    try {
      const validator = new IpValidator(config.ipAllowlist!);
      const passed = validator.isAllowed(request.clientIp, request.headers);

      if (!passed) {
        return {
          layer: SecurityLayer.IP_ALLOWLIST,
          passed: false,
          error: `IP address ${request.clientIp} is not in allowlist`,
          errorType: ValidationErrorType.IP_NOT_ALLOWED,
        };
      }

      return {
        layer: SecurityLayer.IP_ALLOWLIST,
        passed: true,
      };
    } catch (error) {
      return {
        layer: SecurityLayer.IP_ALLOWLIST,
        passed: false,
        error: `IP validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        errorType: ValidationErrorType.INTERNAL_ERROR,
      };
    }
  }

  /**
   * Validate TOTP layer
   */
  private validateTotp(
    request: AuthenticationRequest,
    config: QiuthConfig,
    correlationId: string
  ): LayerValidationResult {
    this.log(`[${correlationId}] Validating TOTP`);

    if (!request.totpToken) {
      return {
        layer: SecurityLayer.TOTP_MFA,
        passed: false,
        error: 'TOTP token is required but not provided',
        errorType: ValidationErrorType.MISSING_TOTP_TOKEN,
      };
    }

    try {
      const validator = new TotpValidator(config.totp!);
      const timestamp = request.timestamp
        ? typeof request.timestamp === 'number'
          ? request.timestamp
          : new Date(request.timestamp).getTime()
        : undefined;
      const passed = validator.validate(request.totpToken, timestamp);

      if (!passed) {
        return {
          layer: SecurityLayer.TOTP_MFA,
          passed: false,
          error: 'Invalid or expired TOTP token',
          errorType: ValidationErrorType.INVALID_TOTP_TOKEN,
        };
      }

      return {
        layer: SecurityLayer.TOTP_MFA,
        passed: true,
      };
    } catch (error) {
      return {
        layer: SecurityLayer.TOTP_MFA,
        passed: false,
        error: `TOTP validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        errorType: ValidationErrorType.INTERNAL_ERROR,
      };
    }
  }

  /**
   * Validate certificate layer
   */
  private validateCertificate(
    request: AuthenticationRequest,
    config: QiuthConfig,
    correlationId: string
  ): LayerValidationResult {
    this.log(`[${correlationId}] Validating certificate`);

    if (!request.signature) {
      return {
        layer: SecurityLayer.CERTIFICATE,
        passed: false,
        error: 'Request signature is required but not provided',
        errorType: ValidationErrorType.MISSING_SIGNATURE,
      };
    }

    if (!request.timestamp) {
      return {
        layer: SecurityLayer.CERTIFICATE,
        passed: false,
        error: 'Request timestamp is required for signature verification',
        errorType: ValidationErrorType.EXPIRED_TIMESTAMP,
      };
    }

    try {
      const validator = new CertificateValidator(config.certificate!);
      const passed = validator.verify(
        request.signature,
        request.method,
        request.url,
        request.body,
        request.timestamp
      );

      if (!passed) {
        return {
          layer: SecurityLayer.CERTIFICATE,
          passed: false,
          error: 'Invalid request signature or expired timestamp',
          errorType: ValidationErrorType.INVALID_SIGNATURE,
        };
      }

      return {
        layer: SecurityLayer.CERTIFICATE,
        passed: true,
      };
    } catch (error) {
      return {
        layer: SecurityLayer.CERTIFICATE,
        passed: false,
        error: `Certificate validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        errorType: ValidationErrorType.INTERNAL_ERROR,
      };
    }
  }

  /**
   * Create validation result
   */
  private createResult(
    success: boolean,
    errors: string[],
    layerResults: LayerValidationResult[],
    startTime: number,
    correlationId: string,
    config?: QiuthConfig
  ): ValidationResult {
    return {
      success,
      errors,
      layerResults,
      config,
      validatedAt: new Date(),
      validationTimeMs: Date.now() - startTime,
      correlationId,
    };
  }

  /**
   * Generate a correlation ID for tracing
   */
  private generateCorrelationId(): string {
    return `qiuth_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }

  /**
   * Log a message if debug is enabled
   */
  private log(message: string, ...args: unknown[]): void {
    if (this.options.debug && this.options.logger) {
      this.options.logger(message, ...args);
    }
  }

  /**
   * Hash an API key (static utility method)
   *
   * @param apiKey - API key to hash
   * @returns Hex-encoded SHA-256 hash
   */
  public static hashApiKey(apiKey: string): string {
    const hash = createHash('sha256');
    hash.update(apiKey);
    return hash.digest('hex');
  }
}
