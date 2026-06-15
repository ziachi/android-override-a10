# CHANGELOG — Android Override (Android 10)

## Commits

| # | Hash | Change |
|---|------|--------|
| 1 | c84d8cf | Initial commit: android-override for Android 10 |
| 2 | bcf0240 | Update README: legal-safe framing |
| 3 | 139ee79 | Add ActivityThread integration patch + build fix docs |
| 4 | e39143b | Adapt session rules: full docs structure |
| 5 | bc8f582 | UI redesign: dark minimalist theme + fix keybox import |
| 6 | 598e7f0 | Remove per-app config and profiles |
| 7 | 13ade62 | Remove SafetyNet/Integrity checker |
| 8 | eeb00e0 | Remove bootloader/verified boot toggles |
| 9 | ad2d70f | Remove auto-fallback toggle |
| 10 | d37746d | Remove TEE/attestation spoof toggle |
| 11 | 1aaf2fa | Integrate Override as always-on — remove master toggle |
| 12 | 0d0a35b | Fix crashes: AboutFragment try/catch + saveConfig mkdirs |
| 13 | c947f75 | Remove Anti-Detection, fix dark theme, fix keybox validation, new icon |
| 14 | 73146bc | Add keystore attestation integration for Device Integrity PASS |
| 15 | 6e77e0c | Fix ROM integration: SEPolicy, KeyboxManager fields, ExportResult API, clearFingerprint |
| 16 | 7dfd111 | Fix init not called: add init() in Activity + mkdirs fallback |
| 17 | a4aaa36 | Update app icon from user-provided cover art |
| 18 | 1a78b83 | Fix cross-process persistence: auto-load config, world-readable, key parsing |
| 19 | da76dd9 | Sync OverrideSettingsActivity with Qassa build |
| 20 | bb546f3 | Sync SEPolicy + file_contexts with Qassa build |

| 21 | 642b180 | Fix cross-process config: /data/system/override + SELinux type |
