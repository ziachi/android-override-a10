# Per-App Spoofing Guide (Android 10)

## Overview

Per-app spoofing lets you configure different device identities
for different apps. Same concept as Android 13+ version but targeting
SafetyNet processes instead of Play Integrity.

## SafetyNet Target Processes

On Android 10, these processes are automatically spoofed:
- `com.google.android.gms` — Main GMS process
- `com.google.android.gms.unstable` — GMS sandbox
- `com.google.android.gms:snet` — SafetyNet process (key!)
- `com.google.android.gms.persistent` — Persistent GMS
- `com.google.process.gapps` — Google apps process

## Configuration

### Via Settings UI

1. Open **Override → Per-App Profiles**
2. Tap **+ Add**
3. Enter package name and desired fingerprint
4. Toggle enabled/disabled per app

### Via Config File

Edit `/data/system/override/config.json`:

```json
{
  "per_app": {
    "com.bank.app": {
      "fingerprint": "samsung/z3q/z3q:10/...",
      "model": "SM-G988B",
      "manufacturer": "samsung",
      "brand": "samsung",
      "enabled": true
    },
    "com.whatsapp": {
      "enabled": false
    }
  }
}
```

## Priority Order

```
Per-app config → Global config → Real device values
```

## Exempt Processes (never spoofed)

- `com.android.settings`
- `com.android.systemui`
- `com.android.shell`
- `android`
- `system_server`
