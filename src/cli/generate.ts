#!/usr/bin/env node

/**
 * Qiuth CLI - Credential Generation Tool
 *
 * Command-line tool for generating Qiuth credentials:
 * - API keys
 * - TOTP secrets
 * - HMAC shared secrets
 * - RSA key pairs
 *
 * @packageDocumentation
 */

import { generateApiKey, generateTotpSecret, generateKeyPair } from '../utils/crypto';
import { QiuthAuthenticator } from '../core/authenticator';
import { TotpValidator } from '../validators/totp-validator';
import { HmacValidator } from '../validators/hmac-validator';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Print usage information
 */
function printUsage(): void {
  console.log(`
Qiuth Credential Generator

Usage:
  qiuth generate <type> [options]

Types:
  api-key       Generate a new API key
  totp          Generate a TOTP secret
  keypair       Generate an RSA key pair
  hmac-secret   Generate an HMAC shared secret
  all           Generate all credentials

Options:
  --length <n>        Length for API key (default: 32 bytes)
  --modulus <n>       RSA key size in bits (default: 2048)
  --output <dir>      Output directory for key files (default: current directory)
  --format <format>   Output format: json, env, text (default: text)
  --hash              Also output hashed API key
  --qr                Generate QR code for TOTP (requires qrcode package)
  --help              Show this help message

Examples:
  qiuth generate api-key
  qiuth generate api-key --length 64 --hash
  qiuth generate totp
  qiuth generate keypair --modulus 4096
  qiuth generate hmac-secret
  qiuth generate hmac-secret --length 64
  qiuth generate all --output ./credentials --format json
  `);
}

/**
 * Generate API key
 */
function generateApiKeyCommand(args: string[]): void {
  const lengthIndex = args.indexOf('--length');
  const length = lengthIndex >= 0 ? parseInt(args[lengthIndex + 1] || '32', 10) : 32;
  const hash = args.includes('--hash');
  const format = getFormat(args);

  const apiKey = generateApiKey(length);
  const hashedApiKey = hash ? QiuthAuthenticator.hashApiKey(apiKey) : undefined;

  if (format === 'json') {
    console.log(JSON.stringify({ apiKey, hashedApiKey }, null, 2));
  } else if (format === 'env') {
    console.log(`QIUTH_API_KEY=${apiKey}`);
    if (hashedApiKey) {
      console.log(`QIUTH_HASHED_API_KEY=${hashedApiKey}`);
    }
  } else {
    console.log('API Key Generated:');
    console.log('==================');
    console.log(`API Key: ${apiKey}`);
    if (hashedApiKey) {
      console.log(`Hashed:  ${hashedApiKey}`);
    }
    console.log('\nWARNING: Store this key securely! It will not be shown again.');
  }
}

/**
 * Generate TOTP secret
 */
function generateTotpCommand(args: string[]): void {
  const format = getFormat(args);
  const qr = args.includes('--qr');

  const secret = generateTotpSecret();
  const validator = new TotpValidator({ enabled: true, secret });
  const currentToken = validator.generate();
  const remainingTime = validator.getRemainingTime();

  if (format === 'json') {
    console.log(JSON.stringify({ secret, currentToken, remainingTime }, null, 2));
  } else if (format === 'env') {
    console.log(`QIUTH_TOTP_SECRET=${secret}`);
  } else {
    console.log('TOTP Secret Generated:');
    console.log('======================');
    console.log(`Secret:        ${secret}`);
    console.log(`Current Token: ${currentToken}`);
    console.log(`Expires in:    ${remainingTime}s`);
    console.log('\nAdd this secret to your authenticator app:');
    console.log(`otpauth://totp/Qiuth?secret=${secret}&issuer=Qiuth`);

    if (qr) {
      console.log('\n(QR code generation requires the qrcode package)');
    }
  }
}

/**
 * Generate RSA key pair
 */
function generateKeypairCommand(args: string[]): void {
  const modulusIndex = args.indexOf('--modulus');
  const modulusLength = modulusIndex >= 0 ? parseInt(args[modulusIndex + 1] || '2048', 10) : 2048;
  const outputIndex = args.indexOf('--output');
  const outputDir = outputIndex >= 0 ? args[outputIndex + 1] || '.' : '.';
  const format = getFormat(args);

  const { publicKey, privateKey } = generateKeyPair({ modulusLength });

  if (format === 'json') {
    console.log(JSON.stringify({ publicKey, privateKey }, null, 2));
  } else if (format === 'env') {
    console.log(`QIUTH_CERTIFICATE_PUBLIC_KEY="${publicKey.replace(/\n/g, '\\n')}"`);
    console.log(`# Store private key securely, not in environment variables`);
  } else {
    // Write to files
    const publicKeyPath = join(outputDir, 'qiuth-public.pem');
    const privateKeyPath = join(outputDir, 'qiuth-private.pem');

    try {
      writeFileSync(publicKeyPath, publicKey);
      writeFileSync(privateKeyPath, privateKey);

      console.log('RSA Key Pair Generated:');
      console.log('=======================');
      console.log(`Key Size:    ${modulusLength} bits`);
      console.log(`Public Key:  ${publicKeyPath}`);
      console.log(`Private Key: ${privateKeyPath}`);
      console.log('\nWARNING: Keep the private key secure! Never commit it to version control.');
    } catch (error) {
      console.error(
        `Error writing key files: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      process.exit(1);
    }
  }
}

/**
 * Generate HMAC shared secret
 */
function generateHmacSecretCommand(args: string[]): void {
  const lengthIndex = args.indexOf('--length');
  const length = lengthIndex >= 0 ? parseInt(args[lengthIndex + 1] || '32', 10) : 32;
  const format = getFormat(args);

  // Ensure minimum length for security
  const effectiveLength = Math.max(length, 32);

  const secret = HmacValidator.generateSecret(effectiveLength);

  if (format === 'json') {
    console.log(JSON.stringify({ hmacSecret: secret, length: effectiveLength }, null, 2));
  } else if (format === 'env') {
    console.log(`QIUTH_HMAC_SECRET=${secret}`);
  } else {
    console.log('HMAC Secret Generated:');
    console.log('======================');
    console.log(`Secret: ${secret}`);
    console.log(`Length: ${effectiveLength} bytes (${effectiveLength * 8} bits)`);
    console.log('\nStore this secret securely on both client and server.');
    console.log('Never expose it in client-side code or version control.');
  }
}

/**
 * Generate all credentials
 */
function generateAllCommand(args: string[]): void {
  const format = getFormat(args);
  const hash = args.includes('--hash');

  const apiKey = generateApiKey();
  const hashedApiKey = hash ? QiuthAuthenticator.hashApiKey(apiKey) : undefined;
  const totpSecret = generateTotpSecret();
  const hmacSecret = HmacValidator.generateSecret();
  const { publicKey, privateKey } = generateKeyPair();

  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          apiKey,
          hashedApiKey,
          totp: { secret: totpSecret },
          hmac: { secret: hmacSecret },
          certificate: { publicKey, privateKey },
        },
        null,
        2
      )
    );
  } else if (format === 'env') {
    console.log('# Qiuth Configuration');
    console.log(`QIUTH_API_KEY=${apiKey}`);
    if (hashedApiKey) {
      console.log(`QIUTH_HASHED_API_KEY=${hashedApiKey}`);
    }
    console.log(`QIUTH_TOTP_SECRET=${totpSecret}`);
    console.log(`QIUTH_HMAC_SECRET=${hmacSecret}`);
    console.log(`QIUTH_CERTIFICATE_PUBLIC_KEY="${publicKey.replace(/\n/g, '\\n')}"`);
    console.log('# Store private key in a secure location');
  } else {
    console.log('All Credentials Generated:');
    console.log('==========================\n');
    console.log(`API Key: ${apiKey}`);
    if (hashedApiKey) {
      console.log(`Hashed:  ${hashedApiKey}`);
    }
    console.log(`\nTOTP Secret: ${totpSecret}`);
    console.log(`\nHMAC Secret: ${hmacSecret}`);
    console.log(`\nPublic Key:\n${publicKey}`);
    console.log(`Private Key:\n${privateKey}`);
    console.log('\nStore these credentials securely!');
  }
}

/**
 * Get output format from args
 */
function getFormat(args: string[]): 'json' | 'env' | 'text' {
  const formatIndex = args.indexOf('--format');
  if (formatIndex >= 0) {
    const format = args[formatIndex + 1];
    if (format === 'json' || format === 'env' || format === 'text') {
      return format;
    }
  }
  return 'text';
}

/**
 * Main CLI entry point
 */
function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  const command = args[0];

  switch (command) {
    case 'generate':
      const type = args[1];
      const subArgs = args.slice(2);

      switch (type) {
        case 'api-key':
          generateApiKeyCommand(subArgs);
          break;
        case 'totp':
          generateTotpCommand(subArgs);
          break;
        case 'keypair':
          generateKeypairCommand(subArgs);
          break;
        case 'hmac-secret':
          generateHmacSecretCommand(subArgs);
          break;
        case 'all':
          generateAllCommand(subArgs);
          break;
        default:
          console.error(`Unknown type: ${type}`);
          printUsage();
          process.exit(1);
      }
      break;

    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(1);
  }
}

// Run CLI if executed directly
if (require.main === module) {
  main();
}

export { main };
