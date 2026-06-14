# Keystore Attestation Integration Guide

How to hook the Override framework into Android 10's Keystore for hardware attestation spoofing.

## Architecture

```
App (GMS) → KeyPairGenerator.generateKeyPair(challenge)
  → AndroidKeyStoreKeyPairGeneratorSpi
  → android.security.KeyStore.attestKey()
  → Keymaster 4.x HAL (HIDL)
  → TEE (real attestation)

With Override:
  → android.security.KeyStore.attestKey()
  → [Override Hook] KeystoreIntegration.generateSpoofedAttestationChain()
    → KeyboxManager (loads imported keybox)
    → AttestationHooks (spoofed security level, boot state)
    → Build leaf cert with challenge + imported keybox key
    → Return [leaf, intermediate, root] from keybox
```

## Components

| File | Purpose |
|------|---------|
| `KeystoreIntegration.java` | Generates spoofed attestation cert chain |
| `AttestationHooks.java` | Provides spoofed security level, boot state, RootOfTrust |
| `KeyboxManager.java` | Loads/manages imported keybox XML (EC + RSA) |
| `OverrideController.java` | Central config (always-on, keybox enabled) |
| `PropsHooks.java` | Build.* field spoofing for GMS processes |

## Integration Steps

### Step 1: Copy Override framework files

```bash
# From ROM root
mkdir -p frameworks/base/core/java/com/android/override/services

# Core
cp patches/frameworks_base/core/OverrideController.java \
   frameworks/base/core/java/com/android/override/
cp patches/frameworks_base/core/PropsHooks.java \
   frameworks/base/core/java/com/android/override/

# Keystore
cp patches/frameworks_base/keystore/AttestationHooks.java \
   frameworks/base/core/java/com/android/override/
cp patches/frameworks_base/keystore/KeyboxManager.java \
   frameworks/base/core/java/com/android/override/
cp patches/frameworks_base/keystore/KeystoreIntegration.java \
   frameworks/base/core/java/com/android/override/

# Services
cp patches/frameworks_base/services/AntiDetection.java \
   frameworks/base/core/java/com/android/override/services/
cp patches/frameworks_base/services/IntegrityChecker.java \
   frameworks/base/core/java/com/android/override/services/
```

### Step 2: Hook into ActivityThread (Build.* spoofing)

Apply `patches/frameworks_base/core/ActivityThread.java.patch`:

```java
// In frameworks/base/core/java/android/app/ActivityThread.java
// Inside handleBindApplication(), BEFORE mInstrumentation.callApplicationOnCreate(app):

import com.android.override.PropsHooks;

// Add:
PropsHooks.onApplicationCreated(app, data.processName);
```

### Step 3: Hook into KeyStore (attestation spoofing)

This is the critical hook. Edit `frameworks/base/keystore/java/android/security/KeyStore.java`:

```java
import com.android.override.KeystoreIntegration;

// In the attestKey method, AFTER the real attestation call:
public int attestKey(String alias, KeymasterArguments params,
                     KeymasterCertificateChain outChain) {
    // Original call
    int result = mBinder.attestKey(alias, params, outChain);

    // Override hook — replace cert chain with imported keybox
    if (result == NO_ERROR && KeystoreIntegration.shouldInterceptAttestation()) {
        try {
            byte[] challenge = params.getBytes(
                KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE, null);

            if (challenge != null) {
                byte[] pubKeyBytes = exportKey(alias,
                    KeymasterDefs.KM_KEY_FORMAT_X509, null, null);

                java.security.KeyFactory kf =
                    java.security.KeyFactory.getInstance("EC");
                java.security.PublicKey pubKey = kf.generatePublic(
                    new java.security.spec.X509EncodedKeySpec(pubKeyBytes));

                java.util.List<byte[]> spoofedChain =
                    KeystoreIntegration.generateSpoofedAttestationChain(
                        pubKey, challenge, null, false);

                if (spoofedChain != null) {
                    outChain.shallowCopyFrom(spoofedChain);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Override attestation hook error", e);
        }
    }

    return result;
}
```

### Step 4: Import keybox on device

Place keybox XML at `/data/system/override/keybox/default.xml` or import via the OverrideSettings app.

Keybox XML format (user must provide their own):
```xml
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="...">
    <Key algorithm="ecdsa">
      <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY-----
      ...
      -----END EC PRIVATE KEY-----</PrivateKey>
      <CertificateChain>
        <NumberOfCertificates>3</NumberOfCertificates>
        <Certificate format="pem">...</Certificate>  <!-- leaf -->
        <Certificate format="pem">...</Certificate>  <!-- intermediate -->
        <Certificate format="pem">...</Certificate>  <!-- root -->
      </CertificateChain>
    </Key>
    <Key algorithm="rsa">
      <!-- Same structure with RSA key -->
    </Key>
  </Keybox>
</AndroidAttestation>
```

**IMPORTANT:** No keybox files are included in this repository. Users must source their own.

## Target: Device Integrity PASS

Requirements for `MEETS_DEVICE_INTEGRITY`:
1. ✅ Build.FINGERPRINT matches certified device (PropsHooks)
2. ✅ SecurityLevel = TrustedEnvironment (AttestationHooks)
3. ✅ VerifiedBoot = Verified, Bootloader = Locked (AttestationHooks)
4. ✅ Valid keybox cert chain (KeyboxManager)
5. ✅ Attestation extension with correct format (KeystoreIntegration)
6. ⚠️ Keybox must NOT be revoked by Google
7. ⚠️ Cert chain must be rooted in Google's attestation root CA

## Keybox Requirements

- Must be a valid, non-revoked keybox
- Supports both ECDSA (P-256) and RSA (2048/4096) keys
- Cert chain should include: leaf → intermediate → Google root CA
- Framework uses EC key by default (preferred for Keymaster 4.x)
- Auto-fallback to RSA if EC fails
- Health monitoring tracks failures and marks potentially revoked keys

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| basicIntegrity FAIL | Root detected | Ensure AntiDetection service is active |
| ctsProfileMatch FAIL | Wrong fingerprint | Check PropsHooks target fingerprint |
| DEVICE_INTEGRITY FAIL | No keybox | Import valid keybox XML |
| DEVICE_INTEGRITY FAIL | Revoked keybox | Try different keybox |
| Cert parse error | HTML comments in PEM | Auto-stripped by KeyboxManager |
| Wrong algorithm | Key type mismatch | Auto-detected from PEM header |
