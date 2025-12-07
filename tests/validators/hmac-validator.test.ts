import { describe, it, expect } from 'vitest';
import { HmacValidator } from '../../src/validators/hmac-validator';
import { HmacConfig } from '../../src/types';

describe('HmacValidator', () => {
  // Minimum 32 character secret for tests
  const validSecret = 'a-very-secure-secret-that-is-32-chars-or-more';

  describe('constructor', () => {
    it('should throw error if HMAC auth is not enabled', () => {
      const config: HmacConfig = {
        enabled: false,
        secret: validSecret,
      };
      expect(() => new HmacValidator(config)).toThrow(
        'HMAC authentication is not enabled in configuration'
      );
    });

    it('should throw error if secret is missing', () => {
      const config: HmacConfig = {
        enabled: true,
        secret: '',
      };
      expect(() => new HmacValidator(config)).toThrow(
        'Shared secret is required when HMAC authentication is enabled'
      );
    });

    it('should throw error if secret is too short', () => {
      const config: HmacConfig = {
        enabled: true,
        secret: 'short-secret',
      };
      expect(() => new HmacValidator(config)).toThrow(
        'HMAC secret must be at least 32 characters for security'
      );
    });

    it('should throw error if maxAge is invalid', () => {
      const config: HmacConfig = {
        enabled: true,
        secret: validSecret,
        maxAge: 0,
      };
      expect(() => new HmacValidator(config)).toThrow('HMAC maxAge must be positive');
    });

    it('should throw error if maxAge is negative', () => {
      const config: HmacConfig = {
        enabled: true,
        secret: validSecret,
        maxAge: -100,
      };
      expect(() => new HmacValidator(config)).toThrow('HMAC maxAge must be positive');
    });

    it('should create validator with valid config', () => {
      const config: HmacConfig = {
        enabled: true,
        secret: validSecret,
      };
      expect(() => new HmacValidator(config)).not.toThrow();
    });

    it('should use default maxAge of 300 seconds', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });
      expect(validator.getMaxAge()).toBe(300);
    });

    it('should use custom maxAge', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
        maxAge: 600,
      });
      expect(validator.getMaxAge()).toBe(600);
    });
  });

  describe('generateSecret', () => {
    it('should generate a 64 character hex string by default (32 bytes)', () => {
      const secret = HmacValidator.generateSecret();
      expect(secret).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should generate correct length for custom byte count', () => {
      const secret = HmacValidator.generateSecret(64);
      expect(secret).toMatch(/^[a-f0-9]{128}$/); // 64 bytes = 128 hex chars
    });

    it('should generate unique secrets', () => {
      const secret1 = HmacValidator.generateSecret();
      const secret2 = HmacValidator.generateSecret();
      expect(secret1).not.toBe(secret2);
    });
  });

  describe('sign and verify', () => {
    it('should verify correctly signed request', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);
    });

    it('should verify signed POST request with body', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'POST';
      const url = 'https://api.example.com/users';
      const body = JSON.stringify({ name: 'John Doe' });
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, method, url, body, timestamp);
      expect(validator.verify(signature, method, url, body, timestamp)).toBe(true);
    });

    it('should verify signed request with Buffer body', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'POST';
      const url = 'https://api.example.com/upload';
      const body = Buffer.from('binary data');
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, method, url, body, timestamp);
      expect(validator.verify(signature, method, url, body, timestamp)).toBe(true);
    });

    it('should reject signature with wrong secret', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const wrongSecret = 'a-different-secret-that-is-also-32-chars';
      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(wrongSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(false);
    });

    it('should reject empty signature', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      expect(validator.verify('', 'GET', 'https://api.example.com', undefined, Date.now())).toBe(
        false
      );
    });

    it('should reject invalid signature format (not hex)', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      expect(
        validator.verify('not-a-valid-hex-signature!', 'GET', 'https://api.example.com', undefined, Date.now())
      ).toBe(false);
    });

    it('should reject signature with wrong length', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      // SHA-256 produces 64 hex characters, this is too short
      expect(
        validator.verify('abcdef123456', 'GET', 'https://api.example.com', undefined, Date.now())
      ).toBe(false);
    });
  });

  describe('request tampering detection', () => {
    it('should reject if method is changed', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, 'GET', url, undefined, timestamp);
      expect(validator.verify(signature, 'POST', url, undefined, timestamp)).toBe(false);
    });

    it('should reject if URL is changed', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(
        validSecret,
        method,
        'https://api.example.com/users',
        undefined,
        timestamp
      );
      expect(
        validator.verify(signature, method, 'https://api.example.com/admin', undefined, timestamp)
      ).toBe(false);
    });

    it('should reject if body is changed', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'POST';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(
        validSecret,
        method,
        url,
        JSON.stringify({ name: 'John' }),
        timestamp
      );
      expect(
        validator.verify(signature, method, url, JSON.stringify({ name: 'Jane' }), timestamp)
      ).toBe(false);
    });

    it('should reject if timestamp is changed', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp + 1000)).toBe(false);
    });

    it('should handle URL fragments correctly', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const timestamp = Date.now();

      // Fragments should be ignored in signature
      const signature = HmacValidator.sign(
        validSecret,
        method,
        'https://api.example.com/users#section',
        undefined,
        timestamp
      );
      expect(
        validator.verify(signature, method, 'https://api.example.com/users', undefined, timestamp)
      ).toBe(true);
    });

    it('should preserve query strings', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users?page=1&limit=10';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);

      // Different query string should fail
      expect(
        validator.verify(
          signature,
          method,
          'https://api.example.com/users?page=2&limit=10',
          undefined,
          timestamp
        )
      ).toBe(false);
    });
  });

  describe('timestamp validation', () => {
    it('should accept recent timestamp', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
        maxAge: 300,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() - 10000; // 10 seconds ago

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);
    });

    it('should reject old timestamp', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
        maxAge: 300,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() - 400000; // 400 seconds ago (> maxAge)

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(false);
    });

    it('should reject future timestamp beyond tolerance', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() + 120000; // 2 minutes in future (> 60s tolerance)

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(false);
    });

    it('should accept slightly future timestamp within tolerance', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() + 30000; // 30 seconds in future (< 60s tolerance)

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);
    });

    it('should reject missing timestamp', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const signature = HmacValidator.sign(
        validSecret,
        'GET',
        'https://api.example.com',
        undefined,
        Date.now()
      );
      expect(validator.verify(signature, 'GET', 'https://api.example.com', undefined, undefined as any)).toBe(
        false
      );
    });

    it('should handle ISO 8601 timestamp format', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();
      const isoTimestamp = new Date(timestamp).toISOString();

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, isoTimestamp)).toBe(true);
    });

    it('should handle timestamp as string number', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp.toString())).toBe(true);
    });
  });

  describe('isTimestampAcceptable', () => {
    it('should accept current timestamp', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      expect(validator.isTimestampAcceptable(Date.now())).toBe(true);
    });

    it('should reject old timestamp', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
        maxAge: 300,
      });

      const oldTimestamp = Date.now() - 400000;
      expect(validator.isTimestampAcceptable(oldTimestamp)).toBe(false);
    });

    it('should accept ISO 8601 format', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const isoTimestamp = new Date().toISOString();
      expect(validator.isTimestampAcceptable(isoTimestamp)).toBe(true);
    });
  });

  describe('method normalization', () => {
    it('should normalize method to uppercase', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = HmacValidator.sign(validSecret, 'get', url, undefined, timestamp);
      expect(validator.verify(signature, 'GET', url, undefined, timestamp)).toBe(true);
      expect(validator.verify(signature, 'get', url, undefined, timestamp)).toBe(true);
    });
  });

  describe('constant-time comparison', () => {
    it('should use constant-time comparison to prevent timing attacks', () => {
      const validator = new HmacValidator({
        enabled: true,
        secret: validSecret,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();
      const validSignature = HmacValidator.sign(validSecret, method, url, undefined, timestamp);

      // Both should take similar time regardless of how different the signatures are
      // This is a basic check - real timing attack tests require more sophisticated measurement
      const start1 = process.hrtime.bigint();
      validator.verify(validSignature.replace('a', 'b'), method, url, undefined, timestamp);
      const time1 = process.hrtime.bigint() - start1;

      const start2 = process.hrtime.bigint();
      validator.verify('0'.repeat(64), method, url, undefined, timestamp);
      const time2 = process.hrtime.bigint() - start2;

      // Times should be in similar order of magnitude (within 10x)
      // This is a weak check but validates the basic implementation
      const ratio = Number(time1) / Number(time2);
      expect(ratio).toBeGreaterThan(0.1);
      expect(ratio).toBeLessThan(10);
    });
  });
});
