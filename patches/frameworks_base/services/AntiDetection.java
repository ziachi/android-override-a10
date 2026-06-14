/*
 * Copyright (C) 2025 Android Override Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.android.override.services;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.util.Log;

import com.android.override.OverrideController;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Anti-detection service for hiding custom ROM indicators.
 * Android 10 (API 29) version.
 *
 * Key differences from Android 13+ version:
 * - SafetyNet detection methods (not Play Integrity)
 * - Additional su binary paths for older Android
 * - Legacy package manager query (no MATCH_* flags)
 * - Additional Magisk Hide/MagiskSU paths
 * - Xposed framework detection paths
 *
 * Hides:
 * 1. Root management apps (Magisk, SuperSU, KingRoot, etc.)
 * 2. Xposed/EdXposed/LSPosed framework
 * 3. Custom recovery (TWRP, OrangeFox)
 * 4. Root binary paths (su, busybox)
 * 5. Mount points that reveal custom partitions
 * 6. System properties that indicate modifications
 * 7. Logcat entries that leak root/custom ROM info
 */
public class AntiDetection {

    private static final String TAG = "AntiDetection";

    /**
     * Packages to hide from package manager queries.
     */
    private static final Set<String> ROOT_PACKAGES = new HashSet<>(Arrays.asList(
            // Magisk
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",     // Magisk Delta
            // SuperSU
            "eu.chainfire.supersu",
            "eu.chainfire.supersu.pro",
            // KingRoot
            "com.kingroot.kinguser",
            "com.kingo.root",
            // Other root managers
            "me.phh.superuser",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
            // Xposed
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
            // Custom Recovery
            "me.twrp.twrpapp",
            "com.jrummy.root.browserfree",
            // Root file managers
            "com.speedsoftware.rootexplorer",
            "com.stericson.busybox",
            // Terminal / ADB
            "jackpal.androidterm",
            "com.sec.android.app.launcher",
            // Safetynet test apps
            "rikka.appops",
            "com.tsng.hidemyapplist",
            // Lucky Patcher
            "com.chelpus.lackypatch",
            "com.dimonvideo.luckypatcher",
            "com.forpda.lp"
    ));

    /**
     * Root binary paths to hide.
     * Android 10 has additional legacy paths to check.
     */
    private static final String[] ROOT_PATHS = {
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/sbin/magisk",
            "/system/bin/magisk",
            "/system/xbin/magisk",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/tmp/su",
            "/cache/su",
            // Magisk specific
            "/sbin/.magisk",
            "/sbin/.core",
            "/dev/.magisk",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/ksu",
            // Xposed
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/data/data/de.robv.android.xposed.installer",
            // BusyBox
            "/system/xbin/busybox",
            "/system/bin/busybox",
            "/sbin/busybox",
            // SuperSU
            "/system/etc/supersu",
            "/system/etc/.installed_su_daemon",
            // Custom recovery
            "/cache/recovery/command",
            "/cache/recovery/log",
            "/system/bin/install-recovery.sh",
    };

    /**
     * Properties that indicate root/custom ROM.
     */
    private static final String[] SUSPICIOUS_PROPS = {
            "ro.build.selinux",
            "ro.debuggable",
            "service.adb.root",
            "ro.secure",
            "ro.build.type",             // should be "user"
            "ro.build.tags",             // should be "release-keys"
            "ro.build.display.id",
            "init.svc.su_daemon",
            "init.svc.magiskd",
            "persist.magisk.hide",
    };

    /**
     * Check if a package should be hidden.
     *
     * @param packageName package to check
     * @param callingPackage the app that's asking
     * @return true if the package should be hidden from callingPackage
     */
    public static boolean shouldHidePackage(String packageName, String callingPackage) {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isAntiDetectionEnabled()) {
            return false;
        }

        if (!controller.isHideAppsEnabled()) {
            return false;
        }

        // Don't hide from system
        if (callingPackage == null || callingPackage.equals("android")
                || callingPackage.equals("com.android.settings")) {
            return false;
        }

        // Check built-in root packages
        if (ROOT_PACKAGES.contains(packageName)) {
            return true;
        }

        // Check user-defined hidden apps
        if (controller.isAppHidden(packageName)) {
            return true;
        }

        return false;
    }

    /**
     * Filter package list to remove hidden packages.
     * Used in PackageManagerService.getInstalledPackages().
     */
    public static List<PackageInfo> filterPackageList(
            List<PackageInfo> packages, String callingPackage) {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isAntiDetectionEnabled()
                || !controller.isHideAppsEnabled()) {
            return packages;
        }

        List<PackageInfo> filtered = new ArrayList<>(packages.size());
        for (PackageInfo pkg : packages) {
            if (!shouldHidePackage(pkg.packageName, callingPackage)) {
                filtered.add(pkg);
            }
        }

        int hiddenCount = packages.size() - filtered.size();
        if (hiddenCount > 0) {
            Log.d(TAG, "Hidden " + hiddenCount + " packages from " + callingPackage);
        }

        return filtered;
    }

    /**
     * Filter application list.
     * Used in PackageManagerService.getInstalledApplications().
     */
    public static List<ApplicationInfo> filterApplicationList(
            List<ApplicationInfo> apps, String callingPackage) {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isAntiDetectionEnabled()
                || !controller.isHideAppsEnabled()) {
            return apps;
        }

        List<ApplicationInfo> filtered = new ArrayList<>(apps.size());
        for (ApplicationInfo app : apps) {
            if (!shouldHidePackage(app.packageName, callingPackage)) {
                filtered.add(app);
            }
        }

        return filtered;
    }

    /**
     * Check if a file path should appear to not exist.
     *
     * Hook this in native file access to hide root paths.
     * On Android 10, apps can still use File.exists() directly.
     */
    public static boolean shouldHidePath(String path) {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isAntiDetectionEnabled()) {
            return false;
        }

        for (String rootPath : ROOT_PATHS) {
            if (path.equals(rootPath) || path.startsWith(rootPath + "/")) {
                return true;
            }
        }

        // Hide Magisk tmp directory
        if (path.startsWith("/sbin/.magisk") || path.startsWith("/dev/.magisk")) {
            return true;
        }

        return false;
    }

    /**
     * Get the spoofed value for a system property.
     *
     * @param key property key
     * @param realValue actual value
     * @return spoofed value, or realValue if no spoofing needed
     */
    public static String getSpoofedProperty(String key, String realValue) {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isAntiDetectionEnabled()) {
            return realValue;
        }

        switch (key) {
            case "ro.build.type":
                return "user";
            case "ro.build.tags":
                return "release-keys";
            case "ro.debuggable":
                return "0";
            case "ro.secure":
                return "1";
            case "service.adb.root":
                return "0";
            case "ro.build.selinux":
                return "1";
            case "init.svc.su_daemon":
            case "init.svc.magiskd":
                return ""; // Hide service
            case "persist.magisk.hide":
                return "";
            default:
                return realValue;
        }
    }

    /**
     * Filter /proc/mounts to hide suspicious mount points.
     *
     * SafetyNet on Android 10 reads /proc/mounts to detect
     * Magisk overlay mounts.
     */
    public static String filterMounts(String mountContent) {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isAntiDetectionEnabled()) {
            return mountContent;
        }

        String[] lines = mountContent.split("\n");
        StringBuilder filtered = new StringBuilder();

        for (String line : lines) {
            String lower = line.toLowerCase();
            // Hide Magisk overlay mounts
            if (lower.contains("magisk") || lower.contains("core/mirror")
                    || lower.contains("core/img") || lower.contains("/sbin/.magisk")
                    || lower.contains("tmpfs /sbin") || lower.contains("tmpfs /system/xbin")) {
                continue;
            }
            filtered.append(line).append("\n");
        }

        return filtered.toString();
    }

    /**
     * Check if a logcat line should be suppressed.
     *
     * Prevents leaking root/custom ROM info through logcat.
     * SafetyNet on Android 10 checks logcat output.
     */
    public static boolean shouldSuppressLog(String tag, String message) {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isAntiDetectionEnabled()) {
            return false;
        }

        // Suppress root-related tags
        if (tag != null) {
            String lowerTag = tag.toLowerCase();
            if (lowerTag.contains("magisk") || lowerTag.contains("supersu")
                    || lowerTag.contains("xposed") || lowerTag.contains("edxposed")
                    || lowerTag.contains("lsposed") || lowerTag.contains("riru")
                    || lowerTag.contains("zygisk")) {
                return true;
            }
        }

        // Suppress messages containing root indicators
        if (message != null) {
            String lowerMsg = message.toLowerCase();
            if (lowerMsg.contains("/sbin/su") || lowerMsg.contains("superuser")
                    || lowerMsg.contains("daemonsu") || lowerMsg.contains("magisk")
                    || lowerMsg.contains("xposed bridge") || lowerMsg.contains("zygisk")) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get status info for the Settings UI.
     */
    public static String getStatusInfo() {
        OverrideController controller = OverrideController.getInstance();
        StringBuilder sb = new StringBuilder();

        sb.append("Anti-Detection Status:\n");
        sb.append("  Enabled: ").append(controller.isAntiDetectionEnabled()).append("\n");
        sb.append("  Hide Apps: ").append(controller.isHideAppsEnabled()).append("\n");
        sb.append("  Root packages hidden: ").append(ROOT_PACKAGES.size()).append("\n");
        sb.append("  Root paths monitored: ").append(ROOT_PATHS.length).append("\n");

        // Check for detectable root
        int detectable = 0;
        for (String path : ROOT_PATHS) {
            if (new File(path).exists()) detectable++;
        }
        sb.append("  Detectable root paths: ").append(detectable).append("\n");

        // Custom hidden apps
        sb.append("  Custom hidden apps: ").append(controller.getHiddenApps().size()).append("\n");

        return sb.toString();
    }
}
