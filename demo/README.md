# 🔐 Qiuth Interactive Demo

Experience multi-factor authentication for API keys in action! This demo shows how Qiuth transforms API keys from simple bearer tokens into secure, multi-factor authenticated credentials.

## 🚀 Quick Start (5 minutes)

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Demo Server

```bash
npm run demo
```

The server will start and display your demo credentials. **Save these!**

### 3. Test the Endpoints

Open a new terminal and try the test commands displayed by the server.

## 📊 What You'll See

### Level 1: Basic API Key
```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:3000/api/basic
```
✅ **Result**: Access granted with just the API key

### Level 2: API Key + IP Allowlist
```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:3000/api/with-ip
```
✅ **Result**: Access granted only from allowed IPs (localhost in demo)

### Level 3: API Key + IP + TOTP
```bash
# Get current TOTP token
curl http://localhost:3000/totp/current

# Use it in your request
curl -H "X-API-Key: YOUR_API_KEY" \
     -H "X-TOTP-Token: 123456" \
     http://localhost:3000/api/with-totp
```
✅ **Result**: Access granted with valid TOTP token (changes every 30 seconds)

### Level 4: Full Security (All Three Layers)

**Easy way - Use the helper script:**
```bash
./demo/test-full-auth.sh
```

**Manual way:**
```bash
# Get signature for your request
curl -X POST http://localhost:3000/sign \
     -H "Content-Type: application/json" \
     -d '{"method":"GET","url":"http://localhost:3000/api/full"}'

# Use all credentials
curl -H "X-API-Key: YOUR_API_KEY" \
     -H "X-TOTP-Token: 123456" \
     -H "X-Timestamp: 1234567890" \
     -H "X-Signature: BASE64_SIGNATURE" \
     http://localhost:3000/api/full
```
✅ **Result**: Maximum security - all three layers verified!

> **Note**: The helper script automatically gets fresh TOTP and signature, then immediately makes the request. This is the recommended way to test Level 4.

## 🎯 Demo Features

### Interactive Helpers

1. **Get Current TOTP Token**
   ```bash
   curl http://localhost:3000/totp/current
   ```

2. **Sign a Request**
   ```bash
   curl -X POST http://localhost:3000/sign \
        -H "Content-Type: application/json" \
        -d '{"method":"GET","url":"http://localhost:3000/api/full"}'
   ```

3. **View All Instructions**
   ```bash
   curl http://localhost:3000
   ```

4. **Automatic Restart Upon Change Available**

   Run the following if you'd like to change IP allowlists etc. on the fly without having to manually restart the server. Be sure to reload `http://localhost:3000`
   to get the most up to date API key or grab the new API key from your terminal output. 

   ```bash
   npm run demo:watch
   ```

### Test Failure Scenarios

1. **Wrong API Key**
   ```bash
   curl -H "X-API-Key: wrong-key" http://localhost:3000/api/basic
   ```
   ❌ **Result**: `401 Unauthorized - Invalid API key`

2. **Missing TOTP Token**
   ```bash
   curl -H "X-API-Key: YOUR_API_KEY" http://localhost:3000/api/with-totp
   ```
   ❌ **Result**: `401 Unauthorized - TOTP token required`

3. **Expired TOTP Token**
   ```bash
   # Wait 30+ seconds and use old token
   curl -H "X-API-Key: YOUR_API_KEY" \
        -H "X-TOTP-Token: 123456" \
        http://localhost:3000/api/with-totp
   ```
   ❌ **Result**: `401 Unauthorized - Invalid TOTP token`

4. **Invalid Signature**
   ```bash
   curl -H "X-API-Key: YOUR_API_KEY" \
        -H "X-TOTP-Token: 123456" \
        -H "X-Timestamp: 1234567890" \
        -H "X-Signature: invalid" \
        http://localhost:3000/api/full
   ```
   ❌ **Result**: `401 Unauthorized - Invalid signature`

## 🔍 What This Demonstrates

### Problem: API Keys as Single Points of Failure

Traditional API keys are **bearer tokens** - anyone with the key can use it:
- ❌ If leaked in a `.env` file committed to GitHub → Full access
- ❌ If intercepted in transit → Full access
- ❌ If stolen from logs → Full access
- ❌ No way to verify the caller's identity beyond possession

### Solution: Multi-Factor Authentication for API Keys

Qiuth transforms API keys into **proof-of-possession tokens** requiring multiple factors:

1. **IP Allowlisting** (Layer 1)
   - ✅ Verify requests come from authorized locations
   - ✅ Computationally cheap first line of defense
   - ✅ Blocks attacks from unauthorized networks immediately

2. **TOTP MFA** (Layer 2)
   - ✅ Time-based one-time passwords (changes every 30 seconds)
   - ✅ Works for service accounts (programmatic)
   - ✅ Even if API key is leaked, attacker needs TOTP secret

3. **Certificate Authentication** (Layer 3)
   - ✅ Cryptographic proof of private key possession
   - ✅ Each request must be signed with private key
   - ✅ Prevents replay attacks with timestamp validation
   - ✅ Even if API key + TOTP are leaked, attacker needs private key

### Real-World Impact

**Before Qiuth:**
```bash
# API key leaked in GitHub
API_KEY=sk_live_abc123

# Attacker has full access
curl -H "Authorization: Bearer sk_live_abc123" https://api.example.com/data
# ✅ Success - Attacker gets all your data
```

**After Qiuth:**
```bash
# API key leaked in GitHub
API_KEY=sk_live_abc123

# Attacker tries to use it
curl -H "X-API-Key: sk_live_abc123" https://api.example.com/data
# ❌ 401 Unauthorized - IP not in allowlist

# Attacker spoofs IP somehow
curl -H "X-API-Key: sk_live_abc123" --interface allowed-ip https://api.example.com/data
# ❌ 401 Unauthorized - TOTP token required

# Attacker gets TOTP secret somehow
curl -H "X-API-Key: sk_live_abc123" -H "X-TOTP-Token: 123456" https://api.example.com/data
# ❌ 401 Unauthorized - Invalid signature (needs private key)

# Attacker would need ALL THREE:
# 1. API key (leaked)
# 2. TOTP secret (leaked)
# 3. Private key (never leaves secure environment)
# = Virtually impossible to compromise
```

## 🔐 Certificate Authentication Deep Dive

Certificate authentication (Level 4) is the strongest security layer. It requires cryptographic proof that you possess the private key.

### How It Works

1. **Client signs the request** with their private key:
   - Method (GET, POST, etc.)
   - Full URL (including protocol, host, path)
   - Request body (if any)
   - Timestamp (prevents replay attacks)

2. **Server verifies the signature** using the public key:
   - Reconstructs the same canonical request
   - Verifies the signature matches
   - Checks timestamp is recent (within 5 minutes by default)

3. **If valid**, request is authenticated. If not, rejected.

### Why Certificate Auth Can Be Tricky

Certificate authentication requires **exact matching** of request details. Common issues:

#### Issue 1: Invalid API Key
**Problem**: The helper script has a hardcoded API key that doesn't match the server's key.

**Solution**: The updated helper script now automatically fetches the API key from the server.

#### Issue 2: URL Mismatch
**Problem**: You sign for `http://localhost:3000/api/full` but the server sees a different URL format.

**Solution**: Always use the exact same URL format. The demo uses `localhost`.

#### Issue 3: Timestamp Expiration
**Problem**: Signatures include a timestamp. If you wait too long between generating and using it, it expires (5 minute default).

**Solution**: Generate the signature immediately before making the request. The helper script does this automatically.

#### Issue 4: Body Mismatch
**Problem**: For GET requests, Express creates an empty object `{}` even when there's no body. The signature must match this.

**Solution**: The `/sign` endpoint now automatically handles this - it signs GET requests with `"{}"` to match what Express sees.

### Testing Certificate Auth

**Method 1: Use the Helper Script (Recommended)**
```bash
./demo/test-full-auth.sh
```

This script:
1. Gets a fresh TOTP token
2. Generates a fresh signature
3. Immediately makes the request

**Method 2: Manual Testing**
```bash
# Step 1: Get current TOTP
TOTP=$(curl -s http://localhost:3000/totp/current | jq -r '.token')

# Step 2: Get API key
API_KEY=$(curl -s http://localhost:3000/ | jq -r '.credentials.apiKey')

# Step 3: Generate signature
SIGN_DATA=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"http://localhost:3000/api/full"}' \
  http://localhost:3000/sign)
TIMESTAMP=$(echo $SIGN_DATA | jq -r '.timestamp')
SIGNATURE=$(echo $SIGN_DATA | jq -r '.signature')

# Step 4: Make request IMMEDIATELY
curl -H "X-API-Key: $API_KEY" \
     -H "X-TOTP-Token: $TOTP" \
     -H "X-Timestamp: $TIMESTAMP" \
     -H "X-Signature: $SIGNATURE" \
     http://localhost:3000/api/full
```

**Important**: Do steps 3 and 4 quickly (within a few seconds) to avoid timing issues.

### Troubleshooting

**"Invalid request signature or expired timestamp"**

Possible causes:
1. **Timestamp too old**: Generate a fresh signature
2. **URL mismatch**: Verify signed URL matches request URL exactly
3. **Body mismatch**: For POST, ensure body matches what was signed
4. **Wrong private key**: Ensure private key matches the public key

**Debug steps**:
1. Use the helper script: `./demo/test-full-auth.sh`
2. Check the timestamp is recent (within 5 minutes)
3. Verify you're using the correct API key from the server

**"TOTP token invalid"**

Possible causes:
1. **Token expired**: TOTP tokens change every 30 seconds
2. **Wrong token**: Using the secret instead of the token
3. **Clock skew**: Server and client clocks are out of sync

**Solution**:
- Get a fresh token: `curl http://localhost:3000/totp/current`
- Use the `token` field (6 digits), NOT the `secret` field
- Make the request within 30 seconds

**"IP not allowed"**

Possible causes:
1. **Not calling from localhost**: The demo only allows localhost or other IPs added in `demo/config.ts`
2. **IPv4 vs IPv6**: Curl might use IPv6 (::1) or IPv4 (127.0.0.1)

**Solution**:
- The demo allows the following by default: `127.0.0.1`, `::1`, and `::ffff:127.0.0.1`
- If testing remotely, update the IP allowlist in `demo/config.ts`

## 📈 Performance

Watch the server logs to see authentication speed:
- **IP Validation**: < 1ms
- **TOTP Validation**: < 5ms
- **Certificate Validation**: < 10ms
- **Total**: < 20ms for all three layers

## 🛠️ Customization

Edit `demo/config.ts` to:
- Change IP allowlist ranges (see `IP_ALLOWLIST`)
- Adjust TOTP time windows (`TOTP.timeStep`, `TOTP.window`)
- Modify certificate key sizes and signature max age (`CERT_OPTIONS`)
- Add custom endpoints or import handlers into `demo/server.ts`
- Test different scenarios (use `npm run demo:watch` to auto-restart)

## 🎓 Learning Path

1. **Start Simple**: Test Level 1 (API key only)
2. **Add IP Security**: Test Level 2 (API key + IP)
3. **Add MFA**: Test Level 3 (API key + IP + TOTP)
4. **Maximum Security**: Test Level 4 (all three layers)
5. **Test Failures**: Try wrong credentials to see error handling
6. **Explore Code**: Read `demo/server.ts` to see implementation
7. **Customize Options**: Modify values in `demo/config.ts` to try out different behavior

## 🚀 Next Steps

After trying the demo:
1. Read the [Getting Started Guide](../docs/getting-started.md)
2. Check out the [API Reference](../docs/api-reference.md)
3. Integrate Qiuth into your own application

## 💡 Tips

- TOTP tokens expire every 30 seconds - use `/totp/current` to get fresh tokens
- The demo uses localhost IPs - modify for remote testing
- Check server logs to see authentication flow
- Try the failure scenarios to understand error handling

## 🎯 Key Takeaways

1. **API keys alone are not secure** - they're single points of failure
2. **Multi-factor authentication works for service accounts** - not just humans
3. **Defense in depth** - multiple layers provide better security
4. **Easy to integrate** - Qiuth makes MFA simple with Express middleware
5. **Production-ready** - includes logging, metrics, and error handling


# Troubleshooting the localhost:3000 service 

List running processes. 

> ps 

Kill the process like running "npm run demo" 

> kill 69420

---

**Ready to secure your API keys?** Start the demo and see Qiuth in action! 🔐

