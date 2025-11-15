/**
 * IP Address Validation Module
 *
 * Provides IP allowlist validation with support for:
 * - IPv4 and IPv6 addresses
 * - CIDR notation for IP ranges
 * - Proxy header parsing (X-Forwarded-For)
 *
 * @packageDocumentation
 */

import { IpAllowlistConfig } from '../types';
import { isIPv4, isIPv6 } from 'node:net';

/**
 * Validator for IP allowlist security layer
 *
 * This is the first line of defense, checking if requests come from authorized locations.
 * It's computationally cheap and eliminates obvious attacks immediately.
 */
export class IpValidator {
  private readonly config: IpAllowlistConfig;
  private readonly normalizedIpCache: Map<string, string> = new Map();
  private readonly cidrCache: Map<string, { network: string; prefixLen: number }> = new Map();

  /**
   * Create a new IP validator
   * @param config - IP allowlist configuration
   */
  constructor(config: IpAllowlistConfig) {
    if (!config.enabled) {
      throw new Error('IP allowlist is not enabled in configuration');
    }
    if (!config.allowedIps || config.allowedIps.length === 0) {
      throw new Error('IP allowlist cannot be empty when enabled');
    }
    this.config = config;

    // Pre-cache normalized IPs and CIDR ranges for better performance
    this.preloadCaches();
  }

  /**
   * Pre-load caches with normalized IPs and parsed CIDR ranges
   * @private
   */
  private preloadCaches(): void {
    for (const entry of this.config.allowedIps) {
      if (entry.includes('/')) {
        // Cache CIDR parsing
        const [network, prefixLenStr] = entry.split('/');
        if (network && prefixLenStr) {
          const prefixLen = parseInt(prefixLenStr, 10);
          if (!isNaN(prefixLen)) {
            this.cidrCache.set(entry, { network, prefixLen });
          }
        }
      } else {
        // Cache normalized IP
        if (this.isValidIp(entry)) {
          this.normalizedIpCache.set(entry, this.normalizeIp(entry));
        }
      }
    }
  }

  /**
   * Check if an IP address is allowed based on the allowlist
   *
   * @param ip - IP address to check (can be IPv4 or IPv6)
   * @param headers - Optional request headers for proxy parsing
   * @returns true if the IP is allowed, false otherwise
   */
  public isAllowed(ip: string, headers?: Record<string, string | string[] | undefined>): boolean {
    // Extract real client IP if proxy headers should be trusted
    const clientIp = this.extractClientIp(ip, headers);

    // Validate IP format
    if (!this.isValidIp(clientIp)) {
      return false;
    }

    // Normalize client IP once and cache it
    const normalizedClientIp = this.getCachedNormalizedIp(clientIp);

    // Check against allowlist
    return this.config.allowedIps.some((allowedEntry) => {
      if (allowedEntry.includes('/')) {
        // CIDR notation - check if IP is in range (uses cached CIDR data)
        return this.isIpInCidrRangeCached(clientIp, allowedEntry);
      } else {
        // Exact match (uses cached normalized IPs)
        const cachedAllowedIp = this.normalizedIpCache.get(allowedEntry);
        return normalizedClientIp === cachedAllowedIp;
      }
    });
  }

  /**
   * Extract the real client IP from request, considering proxy headers
   *
   * When trustProxy is enabled, parses X-Forwarded-For header to get the original client IP.
   * Takes the leftmost IP (original client) rather than rightmost (last proxy).
   *
   * @param ip - Direct connection IP
   * @param headers - Request headers
   * @returns The client IP to validate
   */
  private extractClientIp(
    ip: string,
    headers?: Record<string, string | string[] | undefined>
  ): string {
    if (!this.config.trustProxy || !headers) {
      return ip;
    }

    const forwardedFor = headers['x-forwarded-for'];
    if (!forwardedFor) {
      return ip;
    }

    // X-Forwarded-For can be a string or array
    const forwardedForStr = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    if (!forwardedForStr) {
      return ip;
    }

    // Take the leftmost IP (original client)
    const ips = forwardedForStr.split(',').map((s) => s.trim());
    return ips[0] || ip;
  }

  /**
   * Validate if a string is a valid IP address (IPv4 or IPv6)
   */
  private isValidIp(ip: string): boolean {
    return isIPv4(ip) || isIPv6(ip);
  }

  /**
   * Get cached normalized IP or normalize and cache it
   * @private
   */
  private getCachedNormalizedIp(ip: string): string {
    const cached = this.normalizedIpCache.get(ip);
    if (cached !== undefined) {
      return cached;
    }

    const normalized = this.normalizeIp(ip);
    this.normalizedIpCache.set(ip, normalized);
    return normalized;
  }

  /**
   * Normalize IP address for comparison
   * Handles IPv6 shorthand notation and IPv4-mapped IPv6 addresses
   */
  private normalizeIp(ip: string): string {
    if (isIPv4(ip)) {
      return ip;
    }

    if (isIPv6(ip)) {
      // Expand IPv6 shorthand
      return this.expandIPv6(ip);
    }

    return ip;
  }

  /**
   * Expand IPv6 address from shorthand notation to full form
   * Example: ::1 -> 0000:0000:0000:0000:0000:0000:0000:0001
   */
  private expandIPv6(ip: string): string {
    // Handle IPv4-mapped IPv6 addresses
    if (ip.includes('.')) {
      const parts = ip.split(':');
      const ipv4Part = parts[parts.length - 1];
      if (ipv4Part && isIPv4(ipv4Part)) {
        // Convert IPv4 to hex
        const ipv4Octets = ipv4Part.split('.').map((octet) => parseInt(octet, 10));
        const hex1 = (((ipv4Octets[0] || 0) << 8) | (ipv4Octets[1] || 0))
          .toString(16)
          .padStart(4, '0');
        const hex2 = (((ipv4Octets[2] || 0) << 8) | (ipv4Octets[3] || 0))
          .toString(16)
          .padStart(4, '0');
        ip = ip.substring(0, ip.lastIndexOf(':') + 1) + hex1 + ':' + hex2;
      }
    }

    // Split on ::
    const sides = ip.split('::');
    if (sides.length === 1) {
      // No :: shorthand
      return ip
        .split(':')
        .map((part) => part.padStart(4, '0'))
        .join(':');
    }

    // Expand :: shorthand
    const left = sides[0] ? sides[0].split(':') : [];
    const right = sides[1] ? sides[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill('0000');

    return [...left, ...middle, ...right].map((part) => part.padStart(4, '0')).join(':');
  }

  /**
   * Check if an IP address falls within a CIDR range using cached data
   *
   * @param ip - IP address to check
   * @param cidr - CIDR notation (e.g., "192.168.1.0/24")
   * @returns true if IP is in range
   * @private
   */
  private isIpInCidrRangeCached(ip: string, cidr: string): boolean {
    const cached = this.cidrCache.get(cidr);
    if (!cached) {
      // Fallback to non-cached version
      return this.isIpInCidrRange(ip, cidr);
    }

    const { network, prefixLen } = cached;

    // Determine IP version
    const ipIsV4 = isIPv4(ip);
    const networkIsV4 = isIPv4(network);

    if (ipIsV4 !== networkIsV4) {
      // IP version mismatch
      return false;
    }

    if (ipIsV4) {
      return this.isIPv4InCidr(ip, network, prefixLen);
    } else {
      return this.isIPv6InCidr(ip, network, prefixLen);
    }
  }

  /**
   * Check if an IP address falls within a CIDR range
   *
   * @param ip - IP address to check
   * @param cidr - CIDR notation (e.g., "192.168.1.0/24")
   * @returns true if IP is in range
   */
  private isIpInCidrRange(ip: string, cidr: string): boolean {
    const [network, prefixLenStr] = cidr.split('/');
    if (!network || !prefixLenStr) {
      return false;
    }

    const prefixLen = parseInt(prefixLenStr, 10);
    if (isNaN(prefixLen)) {
      return false;
    }

    // Determine IP version
    const ipIsV4 = isIPv4(ip);
    const networkIsV4 = isIPv4(network);

    if (ipIsV4 !== networkIsV4) {
      // IP version mismatch
      return false;
    }

    if (ipIsV4) {
      return this.isIPv4InCidr(ip, network, prefixLen);
    } else {
      return this.isIPv6InCidr(ip, network, prefixLen);
    }
  }

  /**
   * Check if IPv4 address is in CIDR range
   */
  private isIPv4InCidr(ip: string, network: string, prefixLen: number): boolean {
    if (prefixLen < 0 || prefixLen > 32) {
      return false;
    }

    const ipInt = this.ipv4ToInt(ip);
    const networkInt = this.ipv4ToInt(network);
    const mask = prefixLen === 0 ? 0 : -1 << (32 - prefixLen);

    return (ipInt & mask) === (networkInt & mask);
  }

  /**
   * Convert IPv4 address to 32-bit integer
   */
  private ipv4ToInt(ip: string): number {
    const octets = ip.split('.').map((octet) => parseInt(octet, 10));
    return (
      (((octets[0] || 0) << 24) |
        ((octets[1] || 0) << 16) |
        ((octets[2] || 0) << 8) |
        (octets[3] || 0)) >>>
      0
    ); // Unsigned right shift to ensure positive number
  }

  /**
   * Check if IPv6 address is in CIDR range
   */
  private isIPv6InCidr(ip: string, network: string, prefixLen: number): boolean {
    if (prefixLen < 0 || prefixLen > 128) {
      return false;
    }

    const ipExpanded = this.expandIPv6(ip);
    const networkExpanded = this.expandIPv6(network);

    const ipParts = ipExpanded.split(':').map((part) => parseInt(part, 16));
    const networkParts = networkExpanded.split(':').map((part) => parseInt(part, 16));

    let bitsToCheck = prefixLen;
    for (let i = 0; i < 8; i++) {
      if (bitsToCheck <= 0) {
        break;
      }

      const ipPart = ipParts[i] || 0;
      const networkPart = networkParts[i] || 0;

      if (bitsToCheck >= 16) {
        // Check full 16-bit segment
        if (ipPart !== networkPart) {
          return false;
        }
        bitsToCheck -= 16;
      } else {
        // Check partial segment
        const mask = (0xffff << (16 - bitsToCheck)) & 0xffff;
        if ((ipPart & mask) !== (networkPart & mask)) {
          return false;
        }
        break;
      }
    }

    return true;
  }
}
