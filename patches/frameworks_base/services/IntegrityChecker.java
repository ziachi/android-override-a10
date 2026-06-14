/*
 * Copyright (C) 2025 Android Override Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.android.override.services;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemProperties;
import android.util.Log;

import com.android.override.AttestationHooks;
import com.android.override.KeyboxManager;
import com.android.override.OverrideController;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * SafetyNet / CTS profile check prediction and diagnostics.
 * Android 10 (API 29) version.
 *
 * Key differences from Android 13+ (Play Integrity) version:
 * - SafetyNet Attestation API (not Play Integrity API)
 * - CTS profile match (not DEVICE integrity verdict)
 * - basicIntegrity check (not BASIC verdict)
 * - No STRONG verdict equivalent in SafetyNet
 * - Different GMS component requirements
 *
 * Predicts SafetyNet results:
 * - basicIntegrity: device passes basic checks
 * - ctsProfileMatch: device matches CTS certified profile
 */
public class IntegrityChecker {

    private static final String TAG = "IntegrityChecker";

    // SafetyNet result levels
    public static final int SN_BASIC_INTEGRITY = 0;
    public static final int SN_CTS_PROFILE_MATCH = 1;

    /**
     * Run full SafetyNet prediction diagnostics.
     *
     * @param context application context
     * @return diagnostics result
     */
    public static SafetyNetDiagnostics runDiagnostics(Context context) {
        SafetyNetDiagnostics diag = new SafetyNetDiagnostics();

        try {
            // Check 1: Override framework status
            checkOverrideStatus(diag);

            // Check 2: Build fingerprint
            checkBuildFingerprint(diag);

            // Check 3: GMS / Play Services
            checkGmsStatus(context, diag);

            // Check 4: Keybox / attestation
            checkKeystoreStatus(diag);

            // Check 5: SELinux status
            checkSELinuxStatus(diag);

            // Check 6: Root detection
            checkRootStatus(diag);

            // Check 7: Build properties
            checkBuildProperties(diag);

            // Check 8: Anti-detection status
            checkAntiDetectionStatus(diag);

            // Predict SafetyNet results
            predictSafetyNetResult(diag);

        } catch (Exception e) {
            Log.e(TAG, "Diagnostics failed", e);
            diag.addIssue("CRITICAL", "Diagnostics error: " + e.getMessage());
        }

        return diag;
    }

    private static void checkOverrideStatus(SafetyNetDiagnostics diag) {
        OverrideController controller = OverrideController.getInstance();

        diag.overrideEnabled = controller.isEnabled();
        if (!diag.overrideEnabled) {
            diag.addIssue("WARNING", "Override framework is disabled");
        }
    }

    private static void checkBuildFingerprint(SafetyNetDiagnostics diag) {
        OverrideController controller = OverrideController.getInstance();

        String fp = controller.getFingerprint();
        diag.hasFingerprint = !fp.isEmpty();

        if (diag.hasFingerprint) {
            // Validate fingerprint format
            // Expected: brand/product/device:version/buildId/buildNumber:type/tags
            boolean valid = fp.contains("/") && fp.contains(":")
                    && fp.endsWith("release-keys");
            diag.fingerprintValid = valid;

            if (!valid) {
                diag.addIssue("WARNING", "Fingerprint format may be invalid");
            }

            // Check for release-keys (required for CTS)
            if (!fp.contains("release-keys")) {
                diag.addIssue("ERROR", "Fingerprint must contain 'release-keys' for CTS match");
            }

            // Check for user build type
            if (!fp.contains(":user/")) {
                diag.addIssue("ERROR", "Fingerprint must be 'user' type for CTS match");
            }
        } else {
            diag.addIssue("ERROR", "No fingerprint set — SafetyNet will fail");
        }
    }

    private static void checkGmsStatus(Context context, SafetyNetDiagnostics diag) {
        PackageManager pm = context.getPackageManager();

        // Check Google Play Services
        try {
            PackageInfo gms = pm.getPackageInfo("com.google.android.gms", 0);
            diag.gmsInstalled = true;
            diag.gmsVersion = gms.versionName;
        } catch (PackageManager.NameNotFoundException e) {
            diag.gmsInstalled = false;
            diag.addIssue("CRITICAL", "Google Play Services not installed");
        }

        // Check Google Services Framework
        try {
            pm.getPackageInfo("com.google.android.gsf", 0);
            diag.gsfInstalled = true;
        } catch (PackageManager.NameNotFoundException e) {
            diag.gsfInstalled = false;
            diag.addIssue("CRITICAL", "Google Services Framework not installed");
        }

        // Check Play Store
        try {
            pm.getPackageInfo("com.android.vending", 0);
            diag.playStoreInstalled = true;
        } catch (PackageManager.NameNotFoundException e) {
            diag.playStoreInstalled = false;
            diag.addIssue("WARNING", "Play Store not installed");
        }

        // Check SafetyNet package
        try {
            pm.getPackageInfo("com.google.android.gms", 0);
            // SafetyNet is part of GMS — if GMS is installed, SafetyNet is available
            diag.safetyNetAvailable = diag.gmsInstalled;
        } catch (PackageManager.NameNotFoundException e) {
            diag.safetyNetAvailable = false;
        }
    }

    private static void checkKeystoreStatus(SafetyNetDiagnostics diag) {
        OverrideController controller = OverrideController.getInstance();

        diag.keyboxEnabled = controller.isKeyboxEnabled();
        if (diag.keyboxEnabled) {
            KeyboxManager keybox = KeyboxManager.getInstance();
            diag.keyboxLoaded = keybox.isLoaded();

            if (keybox.isLoaded()) {
                KeyboxManager.KeyboxHealth health = keybox.checkHealth();
                diag.keyboxHealthy = health.status == KeyboxManager.KeyboxHealth.STATUS_OK;
                diag.keyboxAlgorithm = health.algorithm;
                diag.keyboxRevoked = keybox.isRevoked();

                if (diag.keyboxRevoked) {
                    diag.addIssue("ERROR", "Keybox is likely revoked — CTS match will fail");
                }
            } else {
                diag.addIssue("WARNING", "Keybox enabled but not loaded");
            }
        }

        diag.attestationEnabled = controller.isSpoofAttestationEnabled();
    }

    private static void checkSELinuxStatus(SafetyNetDiagnostics diag) {
        try {
            Process process = Runtime.getRuntime().exec("getenforce");
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String mode = reader.readLine();
            reader.close();

            diag.selinuxEnforcing = "Enforcing".equalsIgnoreCase(mode);
            if (!diag.selinuxEnforcing) {
                diag.addIssue("CRITICAL",
                        "SELinux is " + mode + " — SafetyNet WILL detect this");
            }
        } catch (Exception e) {
            diag.selinuxEnforcing = false;
            diag.addIssue("WARNING", "Could not check SELinux status");
        }
    }

    private static void checkRootStatus(SafetyNetDiagnostics diag) {
        String[] suPaths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/data/local/su", "/data/local/bin/su",
                "/sbin/magisk", "/data/adb/magisk"
        };

        diag.rootDetected = false;
        for (String path : suPaths) {
            if (new File(path).exists()) {
                diag.rootDetected = true;
                diag.addIssue("WARNING", "Root binary detected: " + path);
                break;
            }
        }

        // Check for Magisk
        if (new File("/sbin/.magisk").exists() || new File("/dev/.magisk").exists()) {
            diag.magiskDetected = true;
            OverrideController controller = OverrideController.getInstance();
            if (!controller.isAntiDetectionEnabled()) {
                diag.addIssue("WARNING",
                        "Magisk detected — enable Anti-Detection to hide");
            }
        }
    }

    private static void checkBuildProperties(SafetyNetDiagnostics diag) {
        // Check build type
        String buildType = Build.TYPE;
        if (!"user".equals(buildType)) {
            diag.addIssue("WARNING", "Build type is '" + buildType + "' (should be 'user')");
        }

        // Check build tags
        String tags = Build.TAGS;
        if (!"release-keys".equals(tags)) {
            diag.addIssue("WARNING", "Build tags is '" + tags + "' (should be 'release-keys')");
        }

        // Check debuggable
        String debuggable = SystemProperties.get("ro.debuggable", "0");
        if ("1".equals(debuggable)) {
            diag.addIssue("WARNING", "ro.debuggable=1 — SafetyNet may flag this");
        }
    }

    private static void checkAntiDetectionStatus(SafetyNetDiagnostics diag) {
        OverrideController controller = OverrideController.getInstance();

        diag.antiDetectionEnabled = controller.isAntiDetectionEnabled();
        diag.hideAppsEnabled = controller.isHideAppsEnabled();

        if (diag.rootDetected && !diag.antiDetectionEnabled) {
            diag.addIssue("ERROR",
                    "Root detected but Anti-Detection is OFF — SafetyNet will detect root");
        }
    }

    /**
     * Predict SafetyNet results based on diagnostics.
     */
    private static void predictSafetyNetResult(SafetyNetDiagnostics diag) {
        // basicIntegrity prediction
        // Requirements: no root detected (or hidden), SELinux enforcing
        boolean basicPass = diag.overrideEnabled
                && diag.selinuxEnforcing
                && (!diag.rootDetected || diag.antiDetectionEnabled)
                && diag.gmsInstalled;

        diag.predictedBasicIntegrity = basicPass;

        // ctsProfileMatch prediction
        // Requirements: basicIntegrity + valid fingerprint + keybox (or hardware attestation)
        boolean ctsPass = basicPass
                && diag.hasFingerprint
                && diag.fingerprintValid
                && diag.attestationEnabled
                && diag.keyboxEnabled
                && diag.keyboxLoaded
                && diag.keyboxHealthy
                && !diag.keyboxRevoked;

        diag.predictedCtsProfileMatch = ctsPass;

        // Overall recommendation
        if (ctsPass) {
            diag.recommendation = "All checks passed — SafetyNet should pass basicIntegrity + ctsProfileMatch";
        } else if (basicPass) {
            diag.recommendation = "basicIntegrity should pass, but ctsProfileMatch may fail. ";
            if (!diag.keyboxEnabled || !diag.keyboxLoaded) {
                diag.recommendation += "Import a valid keybox for CTS match.";
            } else if (diag.keyboxRevoked) {
                diag.recommendation += "Keybox is revoked — try a new one.";
            } else if (!diag.hasFingerprint) {
                diag.recommendation += "Set a valid device fingerprint.";
            }
        } else {
            diag.recommendation = "SafetyNet will likely fail. Fix critical issues above.";
        }
    }

    /**
     * Diagnostics result for SafetyNet checks.
     */
    public static class SafetyNetDiagnostics {
        // Override status
        public boolean overrideEnabled = false;

        // Fingerprint
        public boolean hasFingerprint = false;
        public boolean fingerprintValid = false;

        // GMS
        public boolean gmsInstalled = false;
        public String gmsVersion = "";
        public boolean gsfInstalled = false;
        public boolean playStoreInstalled = false;
        public boolean safetyNetAvailable = false;

        // Keybox
        public boolean keyboxEnabled = false;
        public boolean keyboxLoaded = false;
        public boolean keyboxHealthy = false;
        public String keyboxAlgorithm = "";
        public boolean keyboxRevoked = false;

        // Attestation
        public boolean attestationEnabled = false;

        // SELinux
        public boolean selinuxEnforcing = false;

        // Root
        public boolean rootDetected = false;
        public boolean magiskDetected = false;

        // Anti-detection
        public boolean antiDetectionEnabled = false;
        public boolean hideAppsEnabled = false;

        // Predictions
        public boolean predictedBasicIntegrity = false;
        public boolean predictedCtsProfileMatch = false;
        public String recommendation = "";

        // Issues
        public List<String[]> issues = new ArrayList<>();

        public void addIssue(String severity, String message) {
            issues.add(new String[]{severity, message});
            Log.d(TAG, "[" + severity + "] " + message);
        }

        /**
         * Get summary string for Settings UI.
         */
        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== SafetyNet Prediction ===\n\n");

            sb.append("basicIntegrity:  ").append(diag("basicIntegrity", predictedBasicIntegrity)).append("\n");
            sb.append("ctsProfileMatch: ").append(diag("ctsProfileMatch", predictedCtsProfileMatch)).append("\n\n");

            sb.append("--- Component Status ---\n");
            sb.append("Override:         ").append(status(overrideEnabled)).append("\n");
            sb.append("Fingerprint:      ").append(status(hasFingerprint && fingerprintValid)).append("\n");
            sb.append("GMS:              ").append(status(gmsInstalled)).append(gmsVersion.isEmpty() ? "" : " v" + gmsVersion).append("\n");
            sb.append("GSF:              ").append(status(gsfInstalled)).append("\n");
            sb.append("Play Store:       ").append(status(playStoreInstalled)).append("\n");
            sb.append("Keybox:           ").append(keyboxEnabled ? (keyboxLoaded ? (keyboxHealthy ? "✅ Healthy" : "⚠️ Degraded") : "⚠️ Not loaded") : "❌ Disabled").append("\n");
            sb.append("Attestation:      ").append(status(attestationEnabled)).append("\n");
            sb.append("SELinux:          ").append(selinuxEnforcing ? "✅ Enforcing" : "❌ Not enforcing").append("\n");
            sb.append("Root:             ").append(rootDetected ? "⚠️ Detected" : "✅ Not detected").append("\n");
            sb.append("Anti-Detection:   ").append(status(antiDetectionEnabled)).append("\n\n");

            if (!issues.isEmpty()) {
                sb.append("--- Issues (").append(issues.size()).append(") ---\n");
                for (String[] issue : issues) {
                    String icon = "CRITICAL".equals(issue[0]) ? "🔴" :
                                  "ERROR".equals(issue[0]) ? "🟠" : "🟡";
                    sb.append(icon).append(" [").append(issue[0]).append("] ").append(issue[1]).append("\n");
                }
                sb.append("\n");
            }

            sb.append("--- Recommendation ---\n");
            sb.append(recommendation).append("\n");

            return sb.toString();
        }

        private String diag(String name, boolean pass) {
            return pass ? "✅ PASS" : "❌ FAIL";
        }

        private String status(boolean ok) {
            return ok ? "✅" : "❌";
        }
    }
}
