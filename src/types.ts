/**
 * Core type definitions for Qiuth
 *
 * These types define the shape of all data structures used throughout the SDK.
 *
 * @packageDocumentation
 */

/**
 * Security layers available in Qiuth
 */
export enum SecurityLayer {
  /** IP address allowlisting - first line of defense */
  IP_ALLOWLIST = 'IP_ALLOWLIST',
  /** Time-based One-Time Password (TOTP) MFA */
  TOTP_MFA = 'TOTP_MFA',
  /** Certificate-based authentication with request signing */
  CERTIFICATE = 'CERTIFICATE',
  /** HMAC-based authentication with shared secret */
  HMAC = 'HMAC',
}

/**
 * Common validation error types
 */
export enum ValidationErrorType {
  /** API key is missing from the request */
  MISSING_API_KEY = 'MISSING_API_KEY',
  /** API key is invalid or not found */
  INVALID_API_KEY = 'INVALID_API_KEY',
  /** Request IP is not in the allowlist */
  IP_NOT_ALLOWED = 'IP_NOT_ALLOWED',
  /** TOTP token is missing when required */
  MISSING_TOTP_TOKEN = 'MISSING_TOTP_TOKEN',
  /** TOTP token is invalid or expired */
  INVALID_TOTP_TOKEN = 'INVALID_TOTP_TOKEN',
  /** Request signature is missing when required */
  MISSING_SIGNATURE = 'MISSING_SIGNATURE',
  /** Request signature is invalid */
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  /** Request timestamp is too old (replay attack prevention) */
  EXPIRED_TIMESTAMP = 'EXPIRED_TIMESTAMP',
  /** Request timestamp is in the future */
  FUTURE_TIMESTAMP = 'FUTURE_TIMESTAMP',
  /** HMAC signature is missing when required */
  MISSING_HMAC = 'MISSING_HMAC',
  /** HMAC signature is invalid */
  INVALID_HMAC = 'INVALID_HMAC',
  /** Configuration is invalid or incomplete */
  INVALID_CONFIGURATION = 'INVALID_CONFIGURATION',
  /** Internal error during validation */
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}

/**
 * Configuration for IP allowlisting security layer
 */
export interface IpAllowlistConfig {
  /** Whether IP allowlisting is enabled */
  enabled: boolean;
  /** Array of allowed IP addresses and CIDR ranges (e.g., "192.168.1.0/24", "10.0.0.1") */
  allowedIps: string[];
  /**
   * Whether to trust proxy headers like X-Forwarded-For
   * Only enable this if your application is behind a trusted proxy/load balancer
   * @default false
   */
  trustProxy?: boolean;
}

/**
 * Configuration for TOTP (Time-based One-Time Password) MFA layer
 */
export interface TotpConfig {
  /** Whether TOTP MFA is enabled */
  enabled: boolean;
  /**
   * Base32-encoded shared secret for TOTP generation
   * This should be securely generated and stored
   */
  secret: string;
  /**
   * Time step in seconds for TOTP generation
   * @default 30
   */
  timeStep?: number;
  /**
   * Number of time windows to accept before and after current time
   * Allows for clock drift and network latency
   * @default 1 (accepts tokens from 1 window before and after)
   */
  window?: number;
}

/**
 * Configuration for certificate-based authentication layer
 */
export interface CertificateConfig {
  /** Whether certificate authentication is enabled */
  enabled: boolean;
  /**
   * PEM-encoded public key/certificate for signature verification
   * This is the public key corresponding to the client's private key
   */
  publicKey: string;
  /**
   * Optional certificate chain for validation
   * Used for more complex PKI setups
   */
  certificateChain?: string[];
  /**
   * Maximum age of a signed request in seconds
   * Prevents replay attacks by rejecting old signatures
   * @default 300 (5 minutes)
   */
  maxAge?: number;
}

/**
 * Configuration for HMAC-based authentication layer
 *
 * HMAC provides a lighter-weight alternative to certificate authentication
 * using shared secrets instead of public-key cryptography.
 */
export interface HmacConfig {
  /** Whether HMAC authentication is enabled */
  enabled: boolean;
  /**
   * Shared secret for HMAC computation
   * Must be at least 32 characters for security
   * Should be securely generated and stored
   */
  secret: string;
  /**
   * Maximum age of a signed request in seconds
   * Prevents replay attacks by rejecting old signatures
   * @default 300 (5 minutes)
   */
  maxAge?: number;
}

/**
 * Complete configuration for a single API key
 *
 * This represents all security settings for one API key.
 * Each security layer can be independently enabled or disabled.
 */
export interface QiuthConfig {
  /**
   * Hashed API key for secure storage
   * Never store plaintext API keys - always hash them
   */
  hashedApiKey: string;
  /**
   * IP allowlisting configuration
   * When enabled, only requests from allowed IPs are accepted
   */
  ipAllowlist?: IpAllowlistConfig;
  /**
   * TOTP MFA configuration
   * When enabled, requests must include a valid TOTP token
   */
  totp?: TotpConfig;
  /**
   * Certificate-based authentication configuration
   * When enabled, requests must be signed with the private key
   */
  certificate?: CertificateConfig;
  /**
   * HMAC-based authentication configuration
   * When enabled, requests must include a valid HMAC signature
   * Lighter-weight alternative to certificate authentication
   */
  hmac?: HmacConfig;
  /**
   * Optional metadata for this API key
   * Can be used for logging, monitoring, or application-specific purposes
   */
  metadata?: Record<string, unknown>;
}

/**
 * Represents an incoming authentication request to be validated
 *
 * This contains all information needed to validate a request
 * against the configured security layers.
 */
export interface AuthenticationRequest {
  /**
   * The API key being used for authentication
   * This will be hashed and compared against the stored hash
   */
  apiKey: string;
  /**
   * Client's IP address
   * Used for IP allowlist validation
   */
  clientIp: string;
  /**
   * Optional TOTP token
   * Required if TOTP MFA is enabled in the configuration
   */
  totpToken?: string;
  /**
   * Optional request signature (for certificate authentication)
   * Required if certificate authentication is enabled
   */
  signature?: string;
  /**
   * Optional HMAC signature (for HMAC authentication)
   * Required if HMAC authentication is enabled
   */
  hmacSignature?: string;
  /**
   * HTTP method of the request (GET, POST, etc.)
   * Included in signature to prevent method tampering
   */
  method: string;
  /**
   * Full URL of the request
   * Included in signature to prevent URL tampering
   */
  url: string;
  /**
   * Request body (if any)
   * Included in signature to prevent body tampering
   */
  body?: string | Buffer;
  /**
   * Timestamp of the request (ISO 8601 format or Unix timestamp)
   * Used for replay attack prevention
   */
  timestamp?: string | number;
  /**
   * Optional additional headers
   * May be used for extracting proxy information or other metadata
   */
  headers?: Record<string, string | string[] | undefined>;
}

/**
 * Details about a specific security layer's validation result
 */
export interface LayerValidationResult {
  /** Which security layer this result is for */
  layer: SecurityLayer;
  /** Whether this layer's validation passed */
  passed: boolean;
  /** Error message if validation failed */
  error?: string;
  /** Error type if validation failed */
  errorType?: ValidationErrorType;
  /** Additional details about the validation */
  details?: Record<string, unknown>;
}

/**
 * Result of authentication validation
 *
 * This is returned after validating an authentication request
 * and contains detailed information about the outcome.
 */
export interface ValidationResult {
  /**
   * Whether authentication was successful
   * True only if all enabled security layers passed
   */
  success: boolean;
  /**
   * Array of error messages if validation failed
   * Empty if validation succeeded
   */
  errors: string[];
  /**
   * Detailed results for each security layer
   * Shows which layers passed and which failed
   */
  layerResults: LayerValidationResult[];
  /**
   * The validated API key configuration if successful
   * Undefined if validation failed
   */
  config?: QiuthConfig;
  /**
   * Timestamp when validation occurred
   */
  validatedAt: Date;
  /**
   * Time taken for validation in milliseconds
   * Useful for performance monitoring
   */
  validationTimeMs?: number;
  /**
   * Correlation ID for tracing this validation through logs
   */
  correlationId?: string;
}

/**
 * Options for configuring the Qiuth authenticator
 */
export interface AuthenticatorOptions {
  /**
   * Whether to enable debug logging
   * @default false
   */
  debug?: boolean;
  /**
   * Custom logger function
   * If not provided, uses console.log
   */
  logger?: (message: string, ...args: unknown[]) => void;
  /**
   * Whether to collect metrics
   * @default true
   */
  collectMetrics?: boolean;
}

/**
 * Configuration for credential rotation
 */
export interface RotationConfig {
  /**
   * Transition period in days during which both old and new credentials are valid
   * @default 7
   */
  transitionPeriodDays?: number;
  /**
   * Whether to automatically rotate credentials on schedule
   * @default false
   */
  autoRotate?: boolean;
  /**
   * Rotation interval in days
   * Only used if autoRotate is true
   * @default 90
   */
  rotationIntervalDays?: number;
}

/**
 * State tracking for credential rotation
 */
export interface RotationState {
  /** Current active credentials */
  current: QiuthConfig;
  /** Deprecated credentials still valid during transition */
  deprecated?: QiuthConfig;
  /** When current credentials were created */
  currentCreatedAt: Date;
  /** When deprecated credentials expire */
  deprecatedExpiresAt?: Date;
  /** When next rotation is scheduled */
  nextRotationAt?: Date;
}
