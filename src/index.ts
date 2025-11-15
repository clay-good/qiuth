/**
 * Qiuth - Multi-factor authentication for API keys
 *
 * Provides three complementary security layers:
 * 1. IP Allowlisting - First line of defense verifying authorized locations
 * 2. TOTP-based MFA - Time-based one-time passwords for service accounts
 * 3. Certificate-based Authentication - Proof-of-possession using public-key cryptography
 *
 * @packageDocumentation
 */

// Core types
export * from './types';

// Validators
export * from './validators/ip-validator';
export * from './validators/totp-validator';
export * from './validators/certificate-validator';

// Core orchestration
export * from './core/authenticator';

// Middleware
export * from './middleware/express';

// Client library
export * from './client/qiuth-client';

// Configuration management
export * from './config/config-builder';
export * from './config/env-loader';

// Utilities
export * from './utils/crypto';

// Rotation
export * from './rotation/credential-rotator';

// Observability
export * from './observability/logger';
export * from './observability/metrics';

/**
 * Qiuth version
 */
export const VERSION = '0.1.2';
