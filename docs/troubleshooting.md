# Troubleshooting Guide (Android 10)

## Common Issues

### SafetyNet: basicIntegrity fails

**Checklist:**
1. ✅ Override master switch is ON
2. ✅ Valid fingerprint is set
3. ✅ GMS is installed
4. ✅ SELinux is Enforcing
5. ✅ Anti-detection is ON (if rooted)

**Fix:** Set a known working Android 10 fingerprint from the database.

---

### SafetyNet: ctsProfileMatch fails (basicIntegrity passes)

**Checklist:**
1. ✅ Keybox is imported and loaded
2. ✅ Keybox is NOT revoked
3. ✅ Attestation spoofing is enabled
4. ✅ Bootloader state set to "locked"
5. ✅ Verified boot state set to "green"
6. ✅ Build.TYPE = "user" and Build.TAGS = "release-keys"

---

### Keybox Format for Android 10

Android 10 uses Keymaster 4.x format. The keybox XML should contain:
- `<Keybox algorithm="RSA">` or `<Keybox algorithm="EC">`
- `<PrivateKey>` — PEM encoded
- `<Certificate>` — PEM encoded X.509 chain

---

### Root Still Detected After Enabling Anti-Detection

**Check:**
```bash
# Verify anti-detection is working
adb logcat -s AntiDetection:*

# Check if su binary is visible
adb shell ls /system/xbin/su
adb shell ls /sbin/su

# Check mounts
adb shell cat /proc/mounts | grep magisk
```

For Android 10 with Magisk, ensure MagiskHide is also enabled alongside Override anti-detection.

---

### Settings App Not Showing

```bash
# Check if app is built
ls system/priv-app/OverrideSettings/
# or
ls product/priv-app/OverrideSettings/

# Verify permissions
cat system/etc/permissions/privapp-permissions-override.xml
```

---

## Debug Commands

```bash
# Check Override status
adb logcat -s OverrideController:* PropsHooks:* KeyboxManager:* AttestationHooks:*

# Check SafetyNet directly
adb logcat | grep -i safetynet

# Check current Build values
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.type
adb shell getprop ro.build.tags

# Check SELinux
adb shell getenforce

# Check keybox
adb shell ls -laZ /data/system/override/keybox/
```
