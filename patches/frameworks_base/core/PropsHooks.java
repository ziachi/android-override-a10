/*
 * Copyright (C) 2025 Android Override Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.android.override;

import android.app.Application;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Hooks into application startup to override Build.* fields.
 * Android 10 (API 29) version.
 *
 * Called from ActivityThread.handleBindApplication() to selectively
 * spoof device identity on a per-process basis.
 *
 * Key differences from Android 13+ version:
 * - SafetyNet target processes (not Play Integrity)
 * - GMS Snet process detection
 * - Legacy Build field names
 * - Additional Build.VERSION fields for A10
 */
public class PropsHooks {

    private static final String TAG = "PropsHooks";

    /**
     * Target processes for SafetyNet spoofing.
     * These are the processes that SafetyNet checks run in.
     */
    private static final Set<String> SAFETYNET_PROCESSES = new HashSet<>(Arrays.asList(
            "com.google.android.gms",
            "com.google.android.gms.unstable",
            "com.google.android.gms:snet",          // SafetyNet process
            "com.google.android.gms.persistent",
            "com.google.process.gapps"
    ));

    /**
     * Processes that should NEVER be spoofed.
     */
    private static final Set<String> EXEMPT_PROCESSES = new HashSet<>(Arrays.asList(
            "com.android.settings",
            "com.android.systemui",
            "com.android.shell",
            "android",
            "system_server"
    ));

    /**
     * Hook called from ActivityThread.handleBindApplication().
     *
     * Usage:
     *   // In ActivityThread.java, inside handleBindApplication():
     *   PropsHooks.onApplicationCreated(app, data.processName);
     */
    public static void onApplicationCreated(Application app, String processName) {
        try {
            OverrideController controller = OverrideController.getInstance();

            if (!controller.isEnabled()) {
                return;
            }

            if (processName == null || EXEMPT_PROCESSES.contains(processName)) {
                return;
            }

            // Check if this process should be spoofed
            boolean shouldSpoof = false;

            // Check per-app config first
            OverrideController.PerAppConfig perApp = controller.getPerAppConfig(processName);
            if (perApp != null) {
                if (!perApp.spoofingEnabled) {
                    Log.d(TAG, "Spoofing disabled for: " + processName);
                    return;
                }
                shouldSpoof = true;
            }

            // Check if SafetyNet target process
            if (!shouldSpoof && SAFETYNET_PROCESSES.contains(processName)) {
                shouldSpoof = true;
            }

            if (!shouldSpoof) {
                return;
            }

            // Apply Build.* overrides
            applyBuildOverrides(controller, processName);

            Log.d(TAG, "Props hooked for: " + processName);

        } catch (Exception e) {
            Log.e(TAG, "Error in onApplicationCreated for " + processName, e);
        }
    }

    /**
     * Apply Build.* field overrides via reflection.
     */
    private static void applyBuildOverrides(OverrideController controller, String processName) {
        // Get effective values (per-app > global)
        String fingerprint = controller.getEffectiveFingerprint(processName);
        String model = controller.getEffectiveModel(processName);
        String manufacturer = controller.getManufacturer();
        String product = controller.getProduct();
        String device = controller.getDevice();
        String brand = controller.getBrand();
        String securityPatch = controller.getSecurityPatch();
        int sdkLevel = controller.getSdkLevel();

        // Check per-app specific values
        OverrideController.PerAppConfig perApp = controller.getPerAppConfig(processName);
        if (perApp != null && perApp.spoofingEnabled) {
            if (!TextUtils.isEmpty(perApp.manufacturer)) manufacturer = perApp.manufacturer;
            if (!TextUtils.isEmpty(perApp.product)) product = perApp.product;
            if (!TextUtils.isEmpty(perApp.device)) device = perApp.device;
            if (!TextUtils.isEmpty(perApp.brand)) brand = perApp.brand;
        }

        // Apply overrides
        if (!TextUtils.isEmpty(fingerprint)) {
            setBuildField("FINGERPRINT", fingerprint);
            // Parse fingerprint components
            // Format: brand/product/device:version/buildId/buildNumber:type/tags
            parseFingerprintComponents(fingerprint);
        }
        if (!TextUtils.isEmpty(model)) {
            setBuildField("MODEL", model);
        }
        if (!TextUtils.isEmpty(manufacturer)) {
            setBuildField("MANUFACTURER", manufacturer);
        }
        if (!TextUtils.isEmpty(product)) {
            setBuildField("PRODUCT", product);
        }
        if (!TextUtils.isEmpty(device)) {
            setBuildField("DEVICE", device);
        }
        if (!TextUtils.isEmpty(brand)) {
            setBuildField("BRAND", brand);
        }
        if (!TextUtils.isEmpty(securityPatch)) {
            setVersionField("SECURITY_PATCH", securityPatch);
        }

        // Spoof SDK level if specified and different from default 29
        if (sdkLevel > 0 && sdkLevel != Build.VERSION.SDK_INT) {
            setVersionIntField("SDK_INT", sdkLevel);
        }
    }

    /**
     * Parse fingerprint and set BUILD_TYPE, TAGS, etc.
     */
    private static void parseFingerprintComponents(String fingerprint) {
        try {
            // brand/product/device:version/buildId/buildNumber:type/tags
            int colonIndex = fingerprint.lastIndexOf(':');
            if (colonIndex > 0) {
                String typeAndTags = fingerprint.substring(colonIndex + 1);
                String[] parts = typeAndTags.split("/");
                if (parts.length >= 1) {
                    setBuildField("TYPE", parts[0]);
                }
                if (parts.length >= 2) {
                    setBuildField("TAGS", parts[1]);
                }
            }

            // Extract build ID
            String[] slashParts = fingerprint.split("/");
            if (slashParts.length >= 4) {
                setBuildField("ID", slashParts[3]);
            }

            // Extract version
            int firstColon = fingerprint.indexOf(':');
            if (firstColon > 0 && firstColon < fingerprint.length() - 1) {
                int slashAfterColon = fingerprint.indexOf('/', firstColon);
                if (slashAfterColon > firstColon) {
                    String version = fingerprint.substring(firstColon + 1, slashAfterColon);
                    setVersionField("RELEASE", version);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse fingerprint components", e);
        }
    }

    /**
     * Set a field in android.os.Build via reflection.
     */
    private static void setBuildField(String fieldName, String value) {
        try {
            Field field = Build.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(null, value);
            Log.v(TAG, "Set Build." + fieldName + " = " + truncate(value, 30));
        } catch (NoSuchFieldException e) {
            Log.w(TAG, "Build field not found: " + fieldName);
        } catch (Exception e) {
            Log.w(TAG, "Failed to set Build." + fieldName, e);
        }
    }

    /**
     * Set a field in android.os.Build.VERSION via reflection.
     */
    private static void setVersionField(String fieldName, String value) {
        try {
            Field field = Build.VERSION.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(null, value);
            Log.v(TAG, "Set Build.VERSION." + fieldName + " = " + value);
        } catch (NoSuchFieldException e) {
            Log.w(TAG, "Build.VERSION field not found: " + fieldName);
        } catch (Exception e) {
            Log.w(TAG, "Failed to set Build.VERSION." + fieldName, e);
        }
    }

    /**
     * Set an int field in android.os.Build.VERSION via reflection.
     */
    private static void setVersionIntField(String fieldName, int value) {
        try {
            Field field = Build.VERSION.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(null, value);
            Log.v(TAG, "Set Build.VERSION." + fieldName + " = " + value);
        } catch (Exception e) {
            Log.w(TAG, "Failed to set Build.VERSION." + fieldName, e);
        }
    }

    private static String truncate(String s, int maxLen) {
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
