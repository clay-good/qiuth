/**
 * Credential Rotation System
 *
 * Provides zero-downtime credential rotation with transition periods.
 * Supports rotating API keys, TOTP secrets, and certificates.
 *
 * @packageDocumentation
 */

import { QiuthConfig } from '../types';
import { QiuthAuthenticator } from '../core/authenticator';

/**
 * Rotation state for a credential
 */
export enum CredentialRotationState {
  /** Credential is active and in use */
  ACTIVE = 'ACTIVE',
  /** Credential is being rotated (both old and new are valid) */
  ROTATING = 'ROTATING',
  /** Credential has been rotated (only new is valid) */
  ROTATED = 'ROTATED',
  /** Credential has been revoked (neither old nor new are valid) */
  REVOKED = 'REVOKED',
}

/**
 * Rotation configuration
 */
export interface CredentialRotationConfig {
  /**
   * Transition period in milliseconds
   * During this period, both old and new credentials are valid
   * @default 86400000 (24 hours)
   */
  transitionPeriod?: number;

  /**
   * Whether to automatically complete rotation after transition period
   * @default true
   */
  autoComplete?: boolean;

  /**
   * Warning threshold in milliseconds before rotation completes
   * If set, onRotationWarning will be called when this much time remains
   * @default 3600000 (1 hour)
   */
  warningThreshold?: number;

  /**
   * Callback when rotation starts
   */
  onRotationStart?: (oldConfig: QiuthConfig, newConfig: QiuthConfig) => void;

  /**
   * Callback when rotation completes
   */
  onRotationComplete?: (newConfig: QiuthConfig) => void;

  /**
   * Callback when rotation is revoked
   */
  onRotationRevoke?: (reason: string) => void;

  /**
   * Callback when approaching rotation completion (based on warningThreshold)
   */
  onRotationWarning?: (timeRemaining: number, metadata: CredentialRotationMetadata) => void;
}

/**
 * Rotation metadata
 */
export interface CredentialRotationMetadata {
  /** Current rotation state */
  state: CredentialRotationState;
  /** Timestamp when rotation started */
  startedAt?: Date;
  /** Timestamp when rotation will complete */
  completesAt?: Date;
  /** Timestamp when rotation completed */
  completedAt?: Date;
  /** Old configuration (during rotation) */
  oldConfig?: QiuthConfig;
  /** New configuration */
  newConfig: QiuthConfig;
  /** Reason for revocation (if revoked) */
  revocationReason?: string;
}

/**
 * Credential Rotator
 *
 * Manages credential rotation with zero-downtime transitions.
 *
 * @example
 * ```typescript
 * const rotator = new CredentialRotator(currentConfig);
 *
 * // Start rotation with new credentials
 * const newConfig = rotator.startRotation(newCredentials, {
 *   transitionPeriod: 24 * 60 * 60 * 1000, // 24 hours
 *   onRotationComplete: (config) => {
 *     console.log('Rotation complete!');
 *   },
 * });
 *
 * // During transition, validate with both old and new
 * const result = await rotator.authenticate(request);
 *
 * // Complete rotation manually
 * rotator.completeRotation();
 * ```
 */
export class CredentialRotator {
  private metadata: CredentialRotationMetadata;
  private config: CredentialRotationConfig;
  private authenticator: QiuthAuthenticator;
  private completionTimer?: NodeJS.Timeout;
  private warningTimer?: NodeJS.Timeout;
  private warningTriggered: boolean = false;

  /**
   * Create a new credential rotator
   * @param initialConfig - Initial configuration
   * @param config - Rotation configuration
   */
  constructor(initialConfig: QiuthConfig, config: CredentialRotationConfig = {}) {
    this.metadata = {
      state: CredentialRotationState.ACTIVE,
      newConfig: initialConfig,
    };
    this.config = {
      transitionPeriod: config.transitionPeriod ?? 86400000, // 24 hours
      autoComplete: config.autoComplete ?? true,
      warningThreshold: config.warningThreshold ?? 3600000, // 1 hour
      ...config,
    };
    this.authenticator = new QiuthAuthenticator();
  }

  /**
   * Start credential rotation
   * @param newConfig - New configuration to rotate to
   * @param config - Optional rotation configuration overrides
   * @returns Updated rotation metadata
   */
  public startRotation(
    newConfig: QiuthConfig,
    config?: Partial<CredentialRotationConfig>
  ): CredentialRotationMetadata {
    if (this.metadata.state === CredentialRotationState.ROTATING) {
      throw new Error('Rotation already in progress');
    }

    // Merge config
    if (config) {
      this.config = { ...this.config, ...config };
    }

    const now = new Date();
    const completesAt = new Date(now.getTime() + (this.config.transitionPeriod || 0));

    this.metadata = {
      state: CredentialRotationState.ROTATING,
      startedAt: now,
      completesAt,
      oldConfig: this.metadata.newConfig,
      newConfig,
    };

    // Call callback
    if (this.config.onRotationStart && this.metadata.oldConfig) {
      this.config.onRotationStart(this.metadata.oldConfig, newConfig);
    }

    // Reset warning flag
    this.warningTriggered = false;

    // Schedule warning
    if (this.config.onRotationWarning && this.config.warningThreshold) {
      const warningTime =
        (this.config.transitionPeriod || 0) - this.config.warningThreshold;
      if (warningTime > 0) {
        this.warningTimer = setTimeout(() => {
          this.triggerWarning();
        }, warningTime);
      } else {
        // Warning threshold is greater than transition period, trigger immediately
        this.triggerWarning();
      }
    }

    // Schedule auto-completion
    if (this.config.autoComplete) {
      this.completionTimer = setTimeout(() => {
        this.completeRotation();
      }, this.config.transitionPeriod);
    }

    return this.metadata;
  }

  /**
   * Complete rotation (make only new credentials valid)
   * @returns Updated rotation metadata
   */
  public completeRotation(): CredentialRotationMetadata {
    if (this.metadata.state !== CredentialRotationState.ROTATING) {
      throw new Error('No rotation in progress');
    }

    // Clear timers
    if (this.completionTimer) {
      clearTimeout(this.completionTimer);
      this.completionTimer = undefined;
    }
    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
      this.warningTimer = undefined;
    }

    this.metadata = {
      state: CredentialRotationState.ROTATED,
      startedAt: this.metadata.startedAt,
      completesAt: this.metadata.completesAt,
      completedAt: new Date(),
      newConfig: this.metadata.newConfig,
      oldConfig: undefined, // Clear old config
    };

    // Call callback
    if (this.config.onRotationComplete) {
      this.config.onRotationComplete(this.metadata.newConfig);
    }

    return this.metadata;
  }

  /**
   * Revoke credentials immediately (emergency use)
   * @param reason - Reason for revocation
   * @returns Updated rotation metadata
   */
  public revokeCredentials(reason: string): CredentialRotationMetadata {
    // Clear timers
    if (this.completionTimer) {
      clearTimeout(this.completionTimer);
      this.completionTimer = undefined;
    }
    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
      this.warningTimer = undefined;
    }

    this.metadata = {
      state: CredentialRotationState.REVOKED,
      newConfig: this.metadata.newConfig,
      revocationReason: reason,
    };

    // Call callback
    if (this.config.onRotationRevoke) {
      this.config.onRotationRevoke(reason);
    }

    return this.metadata;
  }

  /**
   * Authenticate request during rotation
   * Tries new credentials first, then old credentials if in rotation
   * @param request - Authentication request
   * @returns Validation result with indication of which credentials were used
   */
  public async authenticate(request: any): Promise<any> {
    if (this.metadata.state === CredentialRotationState.REVOKED) {
      return {
        success: false,
        errors: ['Credentials have been revoked'],
        layerResults: [],
        validatedAt: new Date(),
      };
    }

    // Try new credentials first
    const newResult = await this.authenticator.authenticate(request, this.metadata.newConfig);

    if (newResult.success) {
      return {
        ...newResult,
        credentialVersion: 'new',
      };
    }

    // If rotating, try old credentials
    if (this.metadata.state === CredentialRotationState.ROTATING && this.metadata.oldConfig) {
      const oldResult = await this.authenticator.authenticate(request, this.metadata.oldConfig);

      if (oldResult.success) {
        return {
          ...oldResult,
          credentialVersion: 'old',
          warning: 'Using old credentials during rotation. Please update to new credentials.',
        };
      }
    }

    // Both failed
    return newResult;
  }

  /**
   * Get current rotation metadata
   */
  public getMetadata(): CredentialRotationMetadata {
    return { ...this.metadata };
  }

  /**
   * Get current rotation state
   */
  public getState(): CredentialRotationState {
    return this.metadata.state;
  }

  /**
   * Check if rotation is in progress
   */
  public isRotating(): boolean {
    return this.metadata.state === CredentialRotationState.ROTATING;
  }

  /**
   * Get time remaining in transition period
   * @returns Milliseconds remaining, or 0 if not rotating
   */
  public getTimeRemaining(): number {
    if (this.metadata.state !== CredentialRotationState.ROTATING || !this.metadata.completesAt) {
      return 0;
    }

    const remaining = this.metadata.completesAt.getTime() - Date.now();
    return Math.max(0, remaining);
  }

  /**
   * Cancel rotation and revert to old credentials
   * @returns Updated rotation metadata
   */
  public cancelRotation(): CredentialRotationMetadata {
    if (this.metadata.state !== CredentialRotationState.ROTATING) {
      throw new Error('No rotation in progress');
    }

    // Clear timers
    if (this.completionTimer) {
      clearTimeout(this.completionTimer);
      this.completionTimer = undefined;
    }
    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
      this.warningTimer = undefined;
    }

    // Revert to old config
    this.metadata = {
      state: CredentialRotationState.ACTIVE,
      newConfig: this.metadata.oldConfig!,
    };

    return this.metadata;
  }

  /**
   * Trigger rotation warning callback
   * @private
   */
  private triggerWarning(): void {
    if (this.warningTriggered || !this.config.onRotationWarning) {
      return;
    }

    this.warningTriggered = true;
    const timeRemaining = this.getTimeRemaining();
    this.config.onRotationWarning(timeRemaining, this.getMetadata());
  }

  /**
   * Manually check and trigger warning if threshold has been reached
   * Useful for polling-based monitoring
   */
  public checkWarningThreshold(): void {
    if (
      this.warningTriggered ||
      !this.config.onRotationWarning ||
      !this.config.warningThreshold
    ) {
      return;
    }

    const timeRemaining = this.getTimeRemaining();
    if (timeRemaining > 0 && timeRemaining <= this.config.warningThreshold) {
      this.triggerWarning();
    }
  }

  /**
   * Clean up resources
   */
  public destroy(): void {
    if (this.completionTimer) {
      clearTimeout(this.completionTimer);
      this.completionTimer = undefined;
    }
    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
      this.warningTimer = undefined;
    }
  }
}
