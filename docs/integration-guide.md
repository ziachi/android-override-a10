# Integration Guide (Android 10)

How to integrate `android-override` into your Android 10 custom ROM.

## Prerequisites

- AOSP / LineageOS 17.x based ROM source tree
- Android 10 (API 29)
- Platform signing keys access

## Key Differences from Android 13+ Version

| Feature | Android 13+ | Android 10 |
|---------|-------------|------------|
| Attestation | KeyMint HAL | Keymaster 4.x HAL |
| Integrity | Play Integrity API | SafetyNet Attestation |
| Check levels | BASIC/DEVICE/STRONG | basicIntegrity/ctsProfileMatch |
| Partition | system_ext | system or product |
| Build system | Android.bp (Soong) | Android.bp or Android.mk |

## Quick Integration (3 Steps)

### Step 1: Copy Framework Patches

```bash
# From your ROM root directory
mkdir -p frameworks/base/core/java/com/android/override/services

cp android-override-a10/patches/frameworks_base/core/*.java \
   frameworks/base/core/java/com/android/override/

cp android-override-a10/patches/frameworks_base/keystore/*.java \
   frameworks/base/core/java/com/android/override/

cp android-override-a10/patches/frameworks_base/services/*.java \
   frameworks/base/core/java/com/android/override/services/
```

### Step 2: Add Hook Call

```java
// In frameworks/base/core/java/android/app/ActivityThread.java
// Inside handleBindApplication(), before app.onCreate():

import com.android.override.PropsHooks;

// Add this line:
PropsHooks.onApplicationCreated(app, data.processName);
```

### Step 3: Copy Settings App & SEPolicy

```bash
# Settings app
cp -r android-override-a10/packages/OverrideSettings/ \
      packages/apps/OverrideSettings/

# SEPolicy
cp android-override-a10/sepolicy/override.te \
   device/YOUR_DEVICE/sepolicy/
cp android-override-a10/sepolicy/file_contexts \
   device/YOUR_DEVICE/sepolicy/
```

Add to your device makefile:

```makefile
PRODUCT_PACKAGES += OverrideSettings
BOARD_SEPOLICY_DIRS += device/YOUR_DEVICE/sepolicy
```

## Build & Flash

```bash
source build/envsetup.sh
lunch your_device-userdebug
mka bacon
```

## Android 10 Specific Notes

- SafetyNet uses `basicIntegrity` and `ctsProfileMatch` (not PI verdicts)
- Keymaster 4.x HAL is used for attestation (not KeyMint)
- The Settings app targets API 29 specifically
- Props database includes Android 10-era devices (Pixel 4, S20, etc.)
- Mount filtering includes Magisk legacy paths
- Additional root paths for older su binary locations

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for common issues.
