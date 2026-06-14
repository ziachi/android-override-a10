# Android Override — Android 10 Edition

Portable device spoofing framework for Android 10 (API 29) custom ROMs.

> ⚠️ For Android 13+ (API 33+), see [android-override](https://github.com/ziachi/android-override)

## Features

- 🔑 **Fingerprint Spoofing** — Override `Build.*` fields system-wide or per-app
- 📦 **Keybox Manager** — Import keybox XML for Keymaster 4.x attestation
- 📱 **Per-App Profiles** — Different device identity for each app
- 💾 **Profile System** — Save/load/switch configurations
- ✅ **SafetyNet Checker** — Predict `basicIntegrity` and `ctsProfileMatch`
- 👻 **Anti-Detection** — Hide root, apps, mounts, and modification traces
- 🔄 **Auto-Fallback** — Rotate keybox slots on failure

## Android 10 Differences

| Feature | Android 13+ | Android 10 |
|---------|-------------|------------|
| Attestation HAL | KeyMint | Keymaster 4.x |
| Integrity API | Play Integrity | SafetyNet |
| Check levels | BASIC/DEVICE/STRONG | basicIntegrity/ctsProfileMatch |
| Target SDK | 33+ | 29 |
| Base64 | java.util.Base64 | android.util.Base64 |
| Storage | scoped storage | READ/WRITE_EXTERNAL_STORAGE |

## Architecture

```
android-override-a10/
├── patches/frameworks_base/
│   ├── core/
│   │   ├── OverrideController.java    # Central controller
│   │   └── PropsHooks.java            # Build.* field hooks (SafetyNet)
│   ├── keystore/
│   │   ├── KeyboxManager.java         # Keymaster keybox manager
│   │   └── AttestationHooks.java      # Keymaster attestation hooks
│   └── services/
│       ├── AntiDetection.java         # Root/app/mount hiding
│       └── IntegrityChecker.java      # SafetyNet prediction
├── packages/OverrideSettings/         # Settings UI app (7 fragments)
├── config/                            # Props database & templates
├── sepolicy/                          # SELinux policy
└── docs/                              # Integration & troubleshooting
```

## Quick Start

See [docs/integration-guide.md](docs/integration-guide.md) for full instructions.

```bash
# 1. Copy framework patches
cp -r patches/frameworks_base/core/*.java \
      $ROM/frameworks/base/core/java/com/android/override/
cp -r patches/frameworks_base/keystore/*.java \
      $ROM/frameworks/base/core/java/com/android/override/
cp -r patches/frameworks_base/services/*.java \
      $ROM/frameworks/base/core/java/com/android/override/services/

# 2. Add hook in ActivityThread.java (handleBindApplication)
# PropsHooks.onApplicationCreated(app, data.processName);

# 3. Copy Settings app + SEPolicy
cp -r packages/OverrideSettings/ $ROM/packages/apps/OverrideSettings/
cp sepolicy/* $ROM/device/YOUR_DEVICE/sepolicy/

# 4. Add to device makefile
# PRODUCT_PACKAGES += OverrideSettings
```

## Props Database

Pre-configured Android 10 fingerprints:
- Google Pixel 4 XL (coral)
- Google Pixel 4 (flame)
- Google Pixel 3 XL (crosshatch)
- Samsung Galaxy S20 Ultra (z3q)
- Samsung Galaxy S10+ (beyond2)
- OnePlus 8 Pro (instantnoodle)
- Xiaomi Mi 10 (umi)
- Samsung Galaxy Note 10+ (d2s)

## Compatible ROMs

- LineageOS 17.x
- AOSP Android 10
- Any Android 10-based custom ROM with source tree access

## Security

- **No keybox/keys included** — bring your own
- SELinux must stay Enforcing
- Config stored in `/data/system/override/` (system-only access)

## License

Apache License 2.0 — see [LICENSE](LICENSE)
