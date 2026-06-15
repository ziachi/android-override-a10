# Android Override — Android 10 Edition

> Device identity management framework for Android 10 (API 29) custom ROM development.
> A research and development toolkit for ROM maintainers.

> For Android 13+ (API 33+), see [android-override](https://github.com/ziachi/android-override)

## Disclaimer

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

## Repos

| Repo | Branch | Description |
|------|--------|-------------|
| [android-override-a10](https://github.com/ziachi/android-override-a10/tree/main) | `main` | Framework patches, Settings app, docs (this repo) |
| [android-override](https://github.com/ziachi/android-override/tree/main) | `main` | Android 13+ version |
| [device_xiaomi_santoni_qassa](https://github.com/ziachi/device_xiaomi_santoni_qassa/tree/qassa-dev) | `qassa-dev` | Device tree for santoni (keepQASSA) |

## Build Status

### keepQASSA Sisu v2.4_0.s — Build SUCCESS
- **Device:** Xiaomi Redmi 4X (santoni), MSM8937, ARM64
- **ROM:** keepQASSA Sisu v2.4_0.s (Android 10)
- **ZIP:** `qassa_Sisu-v2.4_0.s-UNOFFICIAL-santoni-20260614-1254-Vanilla-signed.zip` (753MB)
- **MD5:** `372396bc63a7ee186acecf615938303d`
- **Build time:** 19:36
- **Signed:** releasekey (vendor/ziachi-keys)
- **4 build fixes applied** — see [docs/bug-analysis/](docs/bug-analysis/)

## Android 10 Specifics

| Aspect | Android 13+ | Android 10 |
|--------|-------------|------------|
| Attestation HAL | KeyMint | Keymaster 4.x |
| Verification API | Play Integrity | SafetyNet Attestation |
| Target SDK | 33+ | 29 |
| Base64 | java.util.Base64 | android.util.Base64 |
| Storage | Scoped storage | READ/WRITE_EXTERNAL_STORAGE |

## Features

| Feature | Description |
|---------|-------------|
| Fingerprint Spoofing | Configure `Build.*` fields for GMS process identity |
| Keybox Import | Import keybox XML with dual EC + RSA key support |
| Attestation Hook | Keystore-level hook to replace attestation cert chain |
| Hardware Attestation | Spoof SecurityLevel, VerifiedBoot, RootOfTrust |
| Keybox Health | Monitor keybox validity, detect revocation |
| Certificate Parser | Auto-detect algorithm, strip HTML comments from PEM |
| Device Database | Built-in device property presets (public build info) |
| Always-On | No toggles — spoofing is enabled by default |
| OTA-Safe Config | Persist in `/data/system/override/` — survives updates |

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

# 2. Add hooks
# ActivityThread: see patches/frameworks_base/core/ActivityThread.java.patch
# KeyStore attestation: see patches/frameworks_base/keystore/KeyStore.java.patch
# Full guide: docs/keystore-integration.md

# 3. Copy Settings app + SEPolicy
cp -r packages/OverrideSettings/ $ROM/packages/apps/OverrideSettings/
cp sepolicy/* $ROM/device/YOUR_DEVICE/sepolicy/

# 4. Add to device makefile
# PRODUCT_PACKAGES += OverrideSettings
```

## Directory Structure

```
android-override-a10/
├── README.md
├── LICENSE                                # Apache 2.0
├── CHANGELOG.md                           # Commit history table
├── patches/
│   └── frameworks_base/
│       ├── core/
│       │   ├── ActivityThread.java.patch   # Integration hook patch
│       │   ├── OverrideController.java     # Central controller
│       │   └── PropsHooks.java             # Build.* field configuration
│       ├── keystore/
│       │   ├── KeyboxManager.java          # Keymaster certificate manager
│       │   └── AttestationHooks.java       # Attestation configuration
│       └── services/
│           ├── AntiDetection.java          # Environment management
│           └── IntegrityChecker.java       # Health diagnostics
├── packages/
│   └── OverrideSettings/                   # Settings UI app (7 fragments)
├── config/
│   ├── props_database.xml                  # Device property presets
│   ├── default_config.xml                  # Config template
│   └── example_profile.xml                # Example profile
├── sepolicy/
│   ├── override.te                         # SELinux policy
│   └── file_contexts                       # File labels
└── docs/
    ├── integration-guide.md                # Full integration guide
    ├── per-app-spoofing.md                 # Per-app config guide
    ├── troubleshooting.md                  # Common issues + fixes
    ├── build-fixes.md                      # Build fix summary
    └── bug-analysis/                       # Deep analysis per bug
        ├── activitythread-stray-char.md
        ├── webview-lfs.md
        ├── dex2oat-compiler-filter.md
        └── soong-cache.md
```

## Security Model

- **No keys in repo** — certificates are user-provided
- **No proprietary data** — device database contains only public build information
- **SELinux enforcing** — targeted policy rules only
- **Config in /data/system/override/** — system-only access

## Compatible ROMs

- LineageOS 17.x
- AOSP Android 10
- Any Android 10-based custom ROM with source tree access

## Contributing

Contributions are welcome. Please ensure all contributions follow the project's security model — no keys, certificates, or proprietary data.

## License

```
Copyright 2025 Android Override Project

Licensed under the Apache License, Version 2.0
```

See [LICENSE](LICENSE) for full text.

## SELinux Integration

Override uses a custom SELinux type `override_data_file` for cross-process access:

- Config path: `/data/system/override/`
- Type: `override_data_file` (defined in `sepolicy/override.te`)
- system_app: full read/write access
- priv_app (GMS): read-only access for attestation hooks
- Directory created at boot via `init.rc` with `restorecon`
