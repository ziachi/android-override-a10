# Android Override — Android 10 Edition

> Device identity management framework for Android 10 (API 29) custom ROM development.
> A research and development toolkit for ROM maintainers.

> ℹ️ For Android 13+ (API 33+), see [android-override](https://github.com/ziachi/android-override)

## ⚠️ Disclaimer

This project is provided **strictly for educational and research purposes**. It is intended for custom ROM developers and security researchers who need to understand and manage device identity properties in AOSP-based builds.

**This project does NOT:**
- Include any private keys, certificates, or keybox files
- Distribute any proprietary or copyrighted material
- Encourage or facilitate any violation of terms of service
- Bypass any digital rights management (DRM) protections

**Users are solely responsible** for how they use this framework and must comply with all applicable laws and terms of service in their jurisdiction. The authors assume no liability for misuse.

## What is this?

A modular framework for managing device identity properties at the system level in Android 10 custom ROMs. Designed for ROM developers who need to configure `Build.*` fields, manage Keymaster certificates, and handle per-application device property configurations.

**No keys included** — this is a tool only. Users must provide their own configuration.

## Use Cases

- **ROM Development & Testing** — Test how different device configurations affect app compatibility
- **Security Research** — Study device attestation mechanisms (Keymaster 4.x / SafetyNet)
- **Device Configuration** — Manage device properties for custom ROM builds
- **Compatibility Testing** — Verify app behavior across different device profiles

## Android 10 Specifics

| Aspect | Android 13+ | Android 10 |
|--------|-------------|------------|
| Attestation HAL | KeyMint | Keymaster 4.x |
| Verification API | Play Integrity | SafetyNet Attestation |
| Target SDK | 33+ | 29 |
| Base64 | java.util.Base64 | android.util.Base64 |
| Storage | Scoped storage | READ/WRITE_EXTERNAL_STORAGE |

## Features

- 🔧 **Property Management** — Configure `Build.*` fields system-wide or per-app
- 📦 **Certificate Manager** — Import and manage Keymaster certificates (user-provided)
- 📱 **Per-App Configuration** — Different device identity per application for testing
- 💾 **Profile System** — Save/load/switch device configurations
- ✅ **Health Checker** — Validate configuration and predict compatibility
- 🔄 **Auto-Rotation** — Rotate certificate slots on validation failure

## Architecture

```
android-override-a10/
├── patches/frameworks_base/
│   ├── core/
│   │   ├── OverrideController.java    # Central controller
│   │   └── PropsHooks.java            # Build.* field configuration
│   ├── keystore/
│   │   ├── KeyboxManager.java         # Keymaster certificate manager
│   │   └── AttestationHooks.java      # Attestation configuration
│   └── services/
│       ├── AntiDetection.java         # Environment management
│       └── IntegrityChecker.java      # Health diagnostics
├── packages/OverrideSettings/         # Settings UI app (7 fragments)
├── config/                            # Device database & templates
├── sepolicy/                          # SELinux policy
└── docs/                              # Integration & troubleshooting
```

## Quick Start

See [docs/integration-guide.md](docs/integration-guide.md) for full instructions.

```bash
# 1. Copy framework components
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

## Device Database

Pre-configured device property presets (public build info only):
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

## Security Model

- ✅ **No keys in repo** — certificates are user-provided
- ✅ **No proprietary data** — device database contains only public build information
- ✅ **SELinux enforcing** — targeted policy rules only
- ✅ **Config in /data/system/override/** — system-only access

## Contributing

Contributions are welcome. Please ensure all contributions follow the project's security model — no keys, certificates, or proprietary data.

## License

```
Copyright 2025 Android Override Project

Licensed under the Apache License, Version 2.0
```

See [LICENSE](LICENSE) for full text.

## Build Status

### keepQASSA Sisu v2.4_0.s — Build SUCCESS ✅
- **Device:** Xiaomi Redmi 4X (santoni)
- **ZIP:** `qassa_Sisu-v2.4_0.s-UNOFFICIAL-santoni-20260614-1254-Vanilla-signed.zip` (753MB)
- **MD5:** `372396bc63a7ee186acecf615938303d`
- **Build time:** 19:36
- **Signed:** releasekey
- **4 build fixes applied** — see [docs/build-fixes.md](docs/build-fixes.md)
