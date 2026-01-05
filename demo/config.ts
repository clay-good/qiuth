/**
 * Demo configuration for the Qiuth interactive demo.
 *
 * Keep demo-specific configuration here so it's not hard-coded in `server.ts`.
 * Edit these values when testing different scenarios in the demo.
 */

// IPs allowed by the demo (localhost defaults)
export const IP_ALLOWLIST = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];

// TOTP settings used by the demo
// - timeStep: token lifetime in seconds
// - window: number of time steps to accept (allow some clock skew)
export const TOTP = {
  timeStep: 30,
  window: 1,
};

// Certificate generation/auth settings used by the demo
export const CERT_OPTIONS = {
  // RSA modulus length used when generating demo keypair
  modulusLength: 2048,
  // Maximum allowed age of a signed request in seconds (used by verifier)
  maxAge: 300,
};

export default {
  IP_ALLOWLIST,
  TOTP,
  CERT_OPTIONS,
};
