/*
 * Copyright (C) 2025 Android Override Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.android.override;

import android.os.Build;
import android.util.Log;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Hooks into Keymaster HAL attestation responses.
 * Android 10 (API 29) version.
 *
 * Key differences from Android 13+ (KeyMint) version:
 * - Uses Keymaster 4.x attestation format
 * - SafetyNet CTS profile matching (not Play Integrity)
 * - ASN.1 attestation extension OID: 1.3.6.1.4.1.11129.2.1.17
 * - SecurityLevel values: Software(0), TrustedEnvironment(1), StrongBox(2)
 * - RootOfTrust structure for older format
 *
 * This class intercepts attestation record generation to spoof:
 * - Security level (Software → TrustedEnvironment)
 * - Verified boot state (unverified → verified)
 * - Bootloader state (unlocked → locked)
 * - Device properties in attestation record
 */
public class AttestationHooks {

    private static final String TAG = "AttestationHooks";

    // Keymaster security levels (Android 10)
    public static final int SECURITY_LEVEL_SOFTWARE = 0;
    public static final int SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int SECURITY_LEVEL_STRONGBOX = 2;

    // Verified boot state
    public static final int VERIFIED_BOOT_VERIFIED = 0;
    public static final int VERIFIED_BOOT_SELF_SIGNED = 1;
    public static final int VERIFIED_BOOT_UNVERIFIED = 2;
    public static final int VERIFIED_BOOT_FAILED = 3;

    // Keymaster attestation extension OID
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    /**
     * Get the spoofed security level for attestation.
     *
     * Returns TrustedEnvironment to pass SafetyNet CTS profile.
     * StrongBox is NOT spoofable (hardware-backed).
     */
    public static int getSpoofedSecurityLevel() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isSpoofAttestationEnabled()) {
            return SECURITY_LEVEL_SOFTWARE;
        }
        return SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
    }

    /**
     * Get the spoofed verified boot state.
     */
    public static int getSpoofedVerifiedBootState() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isSpoofAttestationEnabled()) {
            return VERIFIED_BOOT_UNVERIFIED;
        }

        String state = controller.getVerifiedBootState();
        switch (state) {
            case "green":
            case "verified":
                return VERIFIED_BOOT_VERIFIED;
            case "yellow":
            case "self_signed":
                return VERIFIED_BOOT_SELF_SIGNED;
            case "orange":
            case "unverified":
                return VERIFIED_BOOT_UNVERIFIED;
            default:
                return VERIFIED_BOOT_VERIFIED;
        }
    }

    /**
     * Check if bootloader should appear locked.
     */
    public static boolean getSpoofedBootloaderLocked() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isSpoofAttestationEnabled()) {
            return false;
        }
        return "locked".equalsIgnoreCase(controller.getBootloaderState());
    }

    /**
     * Hook for Keymaster attestation key generation.
     *
     * Called when Keymaster generates an attestation certificate.
     * Provides the spoofed certificate chain from imported keybox.
     *
     * @return spoofed certificate chain, or null to use default
     */
    public static List<X509Certificate> getSpoofedCertificateChain() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isKeyboxEnabled()) {
            return null;
        }

        KeyboxManager keybox = KeyboxManager.getInstance();
        if (!keybox.isLoaded()) {
            keybox.load();
        }

        if (!keybox.isLoaded()) {
            Log.w(TAG, "Keybox not available for attestation");
            keybox.reportFailure();
            return null;
        }

        List<X509Certificate> chain = keybox.getCertificateChain();
        if (chain.isEmpty()) {
            keybox.reportFailure();
            return null;
        }

        keybox.reportSuccess();
        return chain;
    }

    /**
     * Get the private key for signing attestation certificates.
     *
     * @return private key from keybox, or null
     */
    public static PrivateKey getAttestationPrivateKey() {
        KeyboxManager keybox = KeyboxManager.getInstance();
        if (!keybox.isLoaded()) {
            return null;
        }
        return keybox.getPrivateKey();
    }

    /**
     * Build spoofed attestation application ID.
     *
     * In Android 10, the attestation record includes the calling
     * application's signature hash. This provides the spoofed values.
     */
    public static byte[] getSpoofedAttestationApplicationId(String packageName) {
        // For SafetyNet, GMS needs to see its own valid app ID
        // We don't modify this — return null to use default
        return null;
    }

    /**
     * Get spoofed RootOfTrust for attestation record.
     *
     * Android 10 Keymaster RootOfTrust:
     * - verifiedBootKey: hash of verified boot key
     * - deviceLocked: boolean
     * - verifiedBootState: enum (Verified/SelfSigned/Unverified/Failed)
     * - verifiedBootHash: hash of boot images (A10+)
     */
    public static RootOfTrust getSpoofedRootOfTrust() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isSpoofAttestationEnabled()) {
            return null;
        }

        RootOfTrust rot = new RootOfTrust();
        rot.deviceLocked = getSpoofedBootloaderLocked();
        rot.verifiedBootState = getSpoofedVerifiedBootState();

        // Use a plausible verified boot key hash (32 bytes of zeros = no custom key)
        rot.verifiedBootKey = new byte[32];

        // Use a plausible verified boot hash
        rot.verifiedBootHash = new byte[32];

        return rot;
    }

    /**
     * Get spoofed system properties for attestation.
     *
     * In Android 10, SafetyNet reads these system properties:
     * - ro.build.fingerprint
     * - ro.build.type
     * - ro.build.tags
     * - ro.product.model
     * - ro.product.brand
     *
     * These are already handled by PropsHooks for the GMS process.
     * This method provides additional attestation-specific values.
     */
    public static String getSpoofedBuildFingerprint() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled()) {
            return Build.FINGERPRINT;
        }

        String fp = controller.getFingerprint();
        return !fp.isEmpty() ? fp : Build.FINGERPRINT;
    }

    /**
     * Get spoofed OS version for attestation record.
     */
    public static int getSpoofedOsVersion() {
        // Format: XXYYZZ where XX=major, YY=minor, ZZ=patch
        // Android 10.0.0 = 100000
        return 100000;
    }

    /**
     * Get spoofed OS patch level for attestation record.
     */
    public static int getSpoofedOsPatchLevel() {
        OverrideController controller = OverrideController.getInstance();
        String secPatch = controller.getSecurityPatch();

        if (secPatch != null && secPatch.length() >= 7) {
            try {
                // Format: YYYY-MM-DD → YYYYMM
                String year = secPatch.substring(0, 4);
                String month = secPatch.substring(5, 7);
                return Integer.parseInt(year) * 100 + Integer.parseInt(month);
            } catch (NumberFormatException e) {
                Log.w(TAG, "Invalid security patch format: " + secPatch);
            }
        }

        return 202008; // Default: 2020-08
    }

    /**
     * RootOfTrust data structure.
     * Matches Keymaster 4.x attestation format.
     */
    public static class RootOfTrust {
        public byte[] verifiedBootKey;
        public boolean deviceLocked;
        public int verifiedBootState;
        public byte[] verifiedBootHash;
    }
}
