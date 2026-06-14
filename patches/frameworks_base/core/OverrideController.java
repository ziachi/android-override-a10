/*
 * Copyright (C) 2025 Android Override Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.android.override;

import android.content.Context;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;
import android.util.Xml;

import org.json.JSONArray;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Central controller for the Override spoofing framework.
 * Android 10 (API 29) version.
 *
 * Manages all configuration: fingerprint, keybox, per-app profiles,
 * anti-detection, auto-fallback, and profile saving/loading.
 *
 * Config stored in /data/system/override/ (OTA-safe).
 *
 * Key differences from Android 13+ version:
 * - Uses Keymaster HAL (not KeyMint)
 * - SafetyNet attestation (not Play Integrity)
 * - Compatible with older SELinux policy format
 * - Uses legacy property service APIs
 */
public class OverrideController {

    private static final String TAG = "OverrideController";
    private static final String CONFIG_DIR = "/data/system/override";
    private static final String CONFIG_FILE = CONFIG_DIR + "/config.json";
    private static final String PROFILES_DIR = CONFIG_DIR + "/profiles";
    private static final String KEYBOX_DIR = CONFIG_DIR + "/keybox";
    private static final String PROPS_DB_FILE = CONFIG_DIR + "/props_database.json";

    private static volatile OverrideController sInstance;
    private Context mContext;

    // Configuration state
    private boolean mEnabled = true;
    private String mFingerprint = "";
    private String mModel = "";
    private String mManufacturer = "";
    private String mProduct = "";
    private String mDevice = "";
    private String mBrand = "";
    private String mSecurityPatch = "";
    private int mSdkLevel = 29; // Android 10

    // Keybox
    private boolean mKeyboxEnabled = false;
    private String mActiveKeyboxSlot = "default";

    // Attestation / Anti-detection
    private boolean mSpoofAttestation = true;
    private boolean mAntiDetection = true;
    private boolean mHideApps = false;
    private boolean mAutoFallback = false;
    private String mBootloaderState = "locked";
    private String mVerifiedBootState = "green";

    // Per-app configs
    private Map<String, PerAppConfig> mPerAppConfigs = new HashMap<>();

    // Hidden apps (from anti-detection)
    private Map<String, Boolean> mHiddenApps = new HashMap<>();

    // Profiles
    private String mActiveProfile = "default";

    // Props database
    private Map<String, PropsEntry> mPropsDatabase = new LinkedHashMap<>();

    private OverrideController() {}

    public static OverrideController getInstance() {
        if (sInstance == null) {
            synchronized (OverrideController.class) {
                if (sInstance == null) {
                    sInstance = new OverrideController();
                }
            }
        }
        return sInstance;
    }

    /**
     * Initialize with context (called from BootReceiver or system server).
     */
    public static void init(Context context) {
        OverrideController instance = getInstance();
        instance.mContext = context;
        instance.ensureDirectories();
        instance.loadConfig();
        instance.loadPropsDatabase();
        Log.i(TAG, "OverrideController [A10] initialized"
                + " enabled=" + instance.mEnabled
                + " fp=" + (instance.mFingerprint.length() > 20
                    ? instance.mFingerprint.substring(0, 20) + "..." : instance.mFingerprint));
    }

    // ========== Directories ==========

    private void ensureDirectories() {
        new File(CONFIG_DIR).mkdirs();
        new File(PROFILES_DIR).mkdirs();
        new File(KEYBOX_DIR).mkdirs();
    }

    // ========== Config Load/Save ==========

    private void loadConfig() {
        File configFile = new File(CONFIG_FILE);
        if (!configFile.exists()) {
            Log.d(TAG, "No config file, using defaults");
            return;
        }

        try {
            StringBuilder sb = new StringBuilder();
            FileReader reader = new FileReader(configFile);
            char[] buf = new char[4096];
            int len;
            while ((len = reader.read(buf)) > 0) sb.append(buf, 0, len);
            reader.close();

            JSONObject json = new JSONObject(sb.toString());

            mEnabled = json.optBoolean("enabled", false);
            mFingerprint = json.optString("fingerprint", "");
            mModel = json.optString("model", "");
            mManufacturer = json.optString("manufacturer", "");
            mProduct = json.optString("product", "");
            mDevice = json.optString("device", "");
            mBrand = json.optString("brand", "");
            mSecurityPatch = json.optString("security_patch", "");
            mSdkLevel = json.optInt("sdk_level", 29);
            mKeyboxEnabled = json.optBoolean("keybox_enabled", false);
            mActiveKeyboxSlot = json.optString("active_keybox_slot", "default");
            mSpoofAttestation = json.optBoolean("spoof_attestation", false);
            mAntiDetection = json.optBoolean("anti_detection", false);
            mHideApps = json.optBoolean("hide_apps", false);
            mAutoFallback = json.optBoolean("auto_fallback", false);
            mBootloaderState = json.optString("bootloader_state", "locked");
            mVerifiedBootState = json.optString("verified_boot_state", "green");
            mActiveProfile = json.optString("active_profile", "default");

            // Per-app configs
            JSONObject perApp = json.optJSONObject("per_app");
            if (perApp != null) {
                for (java.util.Iterator<String> it = perApp.keys(); it.hasNext();) {
                    String pkg = it.next();
                    JSONObject appJson = perApp.getJSONObject(pkg);
                    PerAppConfig config = new PerAppConfig(pkg);
                    config.fingerprint = appJson.optString("fingerprint", "");
                    config.model = appJson.optString("model", "");
                    config.manufacturer = appJson.optString("manufacturer", "");
                    config.product = appJson.optString("product", "");
                    config.device = appJson.optString("device", "");
                    config.brand = appJson.optString("brand", "");
                    config.spoofingEnabled = appJson.optBoolean("enabled", true);
                    mPerAppConfigs.put(pkg, config);
                }
            }

            // Hidden apps
            JSONArray hidden = json.optJSONArray("hidden_apps");
            if (hidden != null) {
                for (int i = 0; i < hidden.length(); i++) {
                    mHiddenApps.put(hidden.getString(i), true);
                }
            }

            Log.d(TAG, "Config loaded successfully");
        } catch (Exception e) {
            Log.e(TAG, "Failed to load config", e);
        }
    }

    public synchronized void saveConfig() {
        try {
            JSONObject json = new JSONObject();
            json.put("enabled", mEnabled);
            json.put("fingerprint", mFingerprint);
            json.put("model", mModel);
            json.put("manufacturer", mManufacturer);
            json.put("product", mProduct);
            json.put("device", mDevice);
            json.put("brand", mBrand);
            json.put("security_patch", mSecurityPatch);
            json.put("sdk_level", mSdkLevel);
            json.put("keybox_enabled", mKeyboxEnabled);
            json.put("active_keybox_slot", mActiveKeyboxSlot);
            json.put("spoof_attestation", mSpoofAttestation);
            json.put("anti_detection", mAntiDetection);
            json.put("hide_apps", mHideApps);
            json.put("auto_fallback", mAutoFallback);
            json.put("bootloader_state", mBootloaderState);
            json.put("verified_boot_state", mVerifiedBootState);
            json.put("active_profile", mActiveProfile);

            // Per-app
            JSONObject perApp = new JSONObject();
            for (Map.Entry<String, PerAppConfig> entry : mPerAppConfigs.entrySet()) {
                PerAppConfig c = entry.getValue();
                JSONObject appJson = new JSONObject();
                appJson.put("fingerprint", c.fingerprint);
                appJson.put("model", c.model);
                appJson.put("manufacturer", c.manufacturer);
                appJson.put("product", c.product);
                appJson.put("device", c.device);
                appJson.put("brand", c.brand);
                appJson.put("enabled", c.spoofingEnabled);
                perApp.put(entry.getKey(), appJson);
            }
            json.put("per_app", perApp);

            // Hidden apps
            JSONArray hidden = new JSONArray();
            for (String pkg : mHiddenApps.keySet()) {
                hidden.put(pkg);
            }
            json.put("hidden_apps", hidden);

            // Ensure config directory exists
            File configDir = new File(CONFIG_DIR);
            if (!configDir.exists()) {
                configDir.mkdirs();
            }

            FileWriter writer = new FileWriter(CONFIG_FILE);
            writer.write(json.toString(2));
            writer.close();

            Log.d(TAG, "Config saved");
        } catch (Exception e) {
            Log.e(TAG, "Failed to save config", e);
        }
    }

    // ========== Getters/Setters ==========

    public boolean isEnabled() { return true; }
    public void setEnabled(boolean enabled) { /* always on */ }

    public String getFingerprint() { return mFingerprint; }
    public void setFingerprint(String fp) { mFingerprint = fp; saveConfig(); }

    public String getModel() { return mModel; }
    public void setModel(String model) { mModel = model; saveConfig(); }

    public String getManufacturer() { return mManufacturer; }
    public void setManufacturer(String mfr) { mManufacturer = mfr; saveConfig(); }

    public String getProduct() { return mProduct; }
    public void setProduct(String product) { mProduct = product; saveConfig(); }

    public String getDevice() { return mDevice; }
    public void setDevice(String device) { mDevice = device; saveConfig(); }

    public String getBrand() { return mBrand; }
    public void setBrand(String brand) { mBrand = brand; saveConfig(); }

    public String getSecurityPatch() { return mSecurityPatch; }
    public void setSecurityPatch(String patch) { mSecurityPatch = patch; saveConfig(); }

    public void clearFingerprint() {
        mFingerprint = "";
        mModel = "";
        mManufacturer = "";
        mProduct = "";
        mDevice = "";
        mBrand = "";
        mSecurityPatch = "";
        saveConfig();
    }

    public int getSdkLevel() { return mSdkLevel; }
    public void setSdkLevel(int sdk) { mSdkLevel = sdk; saveConfig(); }

    // Keybox
    public boolean isKeyboxEnabled() { return mKeyboxEnabled; }
    public void setKeyboxEnabled(boolean enabled) { mKeyboxEnabled = enabled; saveConfig(); }

    public String getActiveKeyboxSlot() { return mActiveKeyboxSlot; }
    public void setActiveKeyboxSlot(String slot) { mActiveKeyboxSlot = slot; saveConfig(); }

    public String getActiveKeyboxPath() {
        return KEYBOX_DIR + "/" + mActiveKeyboxSlot + ".xml";
    }

    // Attestation
    public boolean isSpoofAttestationEnabled() { return true; }
    public void setSpoofAttestation(boolean enabled) { /* always on */ }

    // Anti-detection
    public boolean isAntiDetectionEnabled() { return true; }
    public void setAntiDetection(boolean enabled) { /* always on */ }

    public boolean isHideAppsEnabled() { return mHideApps; }
    public void setHideApps(boolean enabled) { mHideApps = enabled; saveConfig(); }

    // Auto-fallback
    public boolean isAutoFallbackEnabled() { return false; }
    public void setAutoFallback(boolean enabled) { mAutoFallback = enabled; saveConfig(); }

    // Boot state
    public String getBootloaderState() { return "locked"; }
    public void setBootloaderState(String state) { /* always locked */ }

    public String getVerifiedBootState() { return mVerifiedBootState; }
    public void setVerifiedBootState(String state) { mVerifiedBootState = state; saveConfig(); }

    // ========== Per-App ==========

    public PerAppConfig getPerAppConfig(String packageName) {
        return mPerAppConfigs.get(packageName);
    }

    public void setPerAppConfig(PerAppConfig config) {
        mPerAppConfigs.put(config.packageName, config);
        saveConfig();
    }

    public void removePerAppConfig(String packageName) {
        mPerAppConfigs.remove(packageName);
        saveConfig();
    }

    public Map<String, PerAppConfig> getAllPerAppConfigs() {
        return new HashMap<>(mPerAppConfigs);
    }

    /**
     * Get effective fingerprint for a process (per-app > global).
     */
    public String getEffectiveFingerprint(String processName) {
        PerAppConfig perApp = getPerAppConfig(processName);
        if (perApp != null && perApp.spoofingEnabled && !TextUtils.isEmpty(perApp.fingerprint)) {
            return perApp.fingerprint;
        }
        return mFingerprint;
    }

    /**
     * Get effective model for a process (per-app > global).
     */
    public String getEffectiveModel(String processName) {
        PerAppConfig perApp = getPerAppConfig(processName);
        if (perApp != null && perApp.spoofingEnabled && !TextUtils.isEmpty(perApp.model)) {
            return perApp.model;
        }
        return mModel;
    }

    /**
     * Get effective brand for a process (per-app > global).
     */
    public String getEffectiveBrand(String processName) {
        PerAppConfig perApp = getPerAppConfig(processName);
        if (perApp != null && perApp.spoofingEnabled && !TextUtils.isEmpty(perApp.brand)) {
            return perApp.brand;
        }
        return mBrand;
    }

    // ========== Hidden Apps ==========

    public boolean isAppHidden(String packageName) {
        return mHiddenApps.containsKey(packageName);
    }

    public void addHiddenApp(String packageName) {
        mHiddenApps.put(packageName, true);
        saveConfig();
    }

    public void removeHiddenApp(String packageName) {
        mHiddenApps.remove(packageName);
        saveConfig();
    }

    public Map<String, Boolean> getHiddenApps() {
        return new HashMap<>(mHiddenApps);
    }

    // ========== Keybox Import ==========

    /**
     * Import a keybox XML to the default slot.
     */
    public boolean importKeybox(String sourcePath) {
        return importKeybox(sourcePath, mActiveKeyboxSlot);
    }

    /**
     * Import a keybox XML to a named slot.
     */
    public boolean importKeybox(String sourcePath, String slotName) {
        try {
            // Ensure directories exist (fallback if init() wasn't called)
            new File(CONFIG_DIR).mkdirs();
            new File(KEYBOX_DIR).mkdirs();

            File source = new File(sourcePath);
            File dest = new File(KEYBOX_DIR + "/" + slotName + ".xml");

            // Validate XML format before copying
            if (!validateKeyboxXml(source)) {
                Log.e(TAG, "Invalid keybox XML format");
                return false;
            }

            // Copy file
            FileInputStream fis = new FileInputStream(source);
            FileOutputStream fos = new FileOutputStream(dest);
            byte[] buf = new byte[8192];
            int len;
            while ((len = fis.read(buf)) > 0) fos.write(buf, 0, len);
            fis.close();
            fos.close();

            // Set permissions
            dest.setReadable(true, false);
            dest.setWritable(true, true);

            mActiveKeyboxSlot = slotName;
            saveConfig();
            Log.i(TAG, "Keybox imported to slot: " + slotName);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to import keybox", e);
            return false;
        }
    }

    /**
     * Validate keybox XML has required structure.
     * Keymaster format (Android 10): expects Keybox with PrivateKey and Certificate.
     */
    /**
     * Validate keybox XML has required structure.
     * Accepts multiple formats:
     * 1. Standard: <AndroidAttestation><Keybox><Key><PrivateKey>+<Certificate>
     * 2. Simple: <Keybox><PrivateKey>+<Certificate>
     * 3. Any XML with private key + certificate data (case-insensitive)
     */
    private boolean validateKeyboxXml(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(fis, "UTF-8");
            int eventType = parser.getEventType();

            boolean hasKeybox = false;
            boolean hasPrivateKey = false;
            boolean hasCertificate = false;

            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG) {
                    String name = parser.getName().toLowerCase();
                    if ("keybox".equals(name) || "androidattestation".equals(name)) {
                        hasKeybox = true;
                    } else if ("privatekey".equals(name) || "key".equals(name)) {
                        hasPrivateKey = true;
                    } else if ("certificate".equals(name) || "certificatechain".equals(name)) {
                        hasCertificate = true;
                    }
                } else if (eventType == XmlPullParser.TEXT) {
                    String text = parser.getText();
                    if (text != null) {
                        if (text.contains("PRIVATE KEY")) hasPrivateKey = true;
                        if (text.contains("CERTIFICATE")) hasCertificate = true;
                    }
                }
                eventType = parser.next();
            }

            boolean valid = hasKeybox && hasPrivateKey && hasCertificate;
            if (!valid) {
                Log.w(TAG, "Keybox validation: keybox=" + hasKeybox
                        + " key=" + hasPrivateKey + " cert=" + hasCertificate);
            }
            return valid;
        } catch (Exception e) {
            Log.e(TAG, "Keybox XML parse error: " + e.getMessage());
            return false;
        }
    }

    /**
     * List available keybox slots.
     */
    public String[] listKeyboxSlots() {
        File dir = new File(KEYBOX_DIR);
        if (!dir.exists()) return new String[0];

        File[] files = dir.listFiles((d, name) -> name.endsWith(".xml"));
        if (files == null) return new String[0];

        String[] slots = new String[files.length];
        for (int i = 0; i < files.length; i++) {
            slots[i] = files[i].getName().replace(".xml", "");
        }
        return slots;
    }

    // ========== Profiles ==========

    public String getActiveProfile() { return mActiveProfile; }

    public boolean saveProfile(String name) {
        try {
            File configFile = new File(CONFIG_FILE);
            File profileFile = new File(PROFILES_DIR + "/" + name + ".json");

            if (configFile.exists()) {
                FileInputStream fis = new FileInputStream(configFile);
                FileOutputStream fos = new FileOutputStream(profileFile);
                byte[] buf = new byte[8192];
                int len;
                while ((len = fis.read(buf)) > 0) fos.write(buf, 0, len);
                fis.close();
                fos.close();
            }

            mActiveProfile = name;
            saveConfig();
            Log.i(TAG, "Profile saved: " + name);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to save profile: " + name, e);
            return false;
        }
    }

    public boolean loadProfile(String name) {
        File profileFile = new File(PROFILES_DIR + "/" + name + ".json");
        if (!profileFile.exists()) {
            Log.w(TAG, "Profile not found: " + name);
            return false;
        }

        try {
            FileInputStream fis = new FileInputStream(profileFile);
            FileOutputStream fos = new FileOutputStream(CONFIG_FILE);
            byte[] buf = new byte[8192];
            int len;
            while ((len = fis.read(buf)) > 0) fos.write(buf, 0, len);
            fis.close();
            fos.close();

            loadConfig();
            mActiveProfile = name;
            saveConfig();
            Log.i(TAG, "Profile loaded: " + name);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to load profile: " + name, e);
            return false;
        }
    }

    public void deleteProfile(String name) {
        new File(PROFILES_DIR + "/" + name + ".json").delete();
    }

    public String[] listProfiles() {
        File dir = new File(PROFILES_DIR);
        if (!dir.exists()) return new String[0];

        File[] files = dir.listFiles((d, n) -> n.endsWith(".json"));
        if (files == null) return new String[0];

        String[] names = new String[files.length];
        for (int i = 0; i < files.length; i++) {
            names[i] = files[i].getName().replace(".json", "");
        }
        return names;
    }

    // ========== Props Database ==========

    private void loadPropsDatabase() {
        // Built-in database of known working device fingerprints for Android 10
        mPropsDatabase.put("Pixel 4 XL (coral)", new PropsEntry(
                "google/coral/coral:10/QQ3A.200805.001/6578210:user/release-keys",
                "Pixel 4 XL", "Google", "coral", "coral", "google", "2020-08-05", 29));

        mPropsDatabase.put("Pixel 4 (flame)", new PropsEntry(
                "google/flame/flame:10/QQ3A.200805.001/6578210:user/release-keys",
                "Pixel 4", "Google", "flame", "flame", "google", "2020-08-05", 29));

        mPropsDatabase.put("Pixel 3 XL (crosshatch)", new PropsEntry(
                "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys",
                "Pixel 3 XL", "Google", "crosshatch", "crosshatch", "google", "2020-08-05", 29));

        mPropsDatabase.put("Samsung S20 Ultra (z3q)", new PropsEntry(
                "samsung/z3q/z3q:10/QP1A.190711.020/G988BXXS9DTL1:user/release-keys",
                "SM-G988B", "samsung", "z3q", "z3q", "samsung", "2020-12-01", 29));

        mPropsDatabase.put("Samsung S10+ (beyond2)", new PropsEntry(
                "samsung/beyond2lte/beyond2:10/QP1A.190711.020/G975FXXS9DTL1:user/release-keys",
                "SM-G975F", "samsung", "beyond2lte", "beyond2", "samsung", "2020-12-01", 29));

        mPropsDatabase.put("OnePlus 8 Pro (instantnoodle)", new PropsEntry(
                "oneplus/OnePlus8Pro/OnePlus8Pro:10/QKQ1.190716.003/2012012019:user/release-keys",
                "IN2023", "OnePlus", "OnePlus8Pro", "OnePlus8Pro", "OnePlus", "2020-12-05", 29));

        mPropsDatabase.put("Xiaomi Mi 10 (umi)", new PropsEntry(
                "xiaomi/umi/umi:10/QKQ1.191117.002/V12.0.3.0.QJBMIXM:user/release-keys",
                "Mi 10", "Xiaomi", "umi", "umi", "Xiaomi", "2020-09-05", 29));

        mPropsDatabase.put("Samsung Note 10+ (d2s)", new PropsEntry(
                "samsung/d2s/d2s:10/QP1A.190711.020/N975FXXS6DTL1:user/release-keys",
                "SM-N975F", "samsung", "d2s", "d2s", "samsung", "2020-12-01", 29));

        // Load custom database from file if exists
        File dbFile = new File(PROPS_DB_FILE);
        if (dbFile.exists()) {
            try {
                StringBuilder sb = new StringBuilder();
                FileReader reader = new FileReader(dbFile);
                char[] buf = new char[4096];
                int len;
                while ((len = reader.read(buf)) > 0) sb.append(buf, 0, len);
                reader.close();

                JSONObject dbJson = new JSONObject(sb.toString());
                for (java.util.Iterator<String> it = dbJson.keys(); it.hasNext();) {
                    String key = it.next();
                    JSONObject entry = dbJson.getJSONObject(key);
                    mPropsDatabase.put(key, new PropsEntry(
                            entry.optString("fingerprint"),
                            entry.optString("model"),
                            entry.optString("manufacturer"),
                            entry.optString("product"),
                            entry.optString("device"),
                            entry.optString("brand"),
                            entry.optString("security_patch"),
                            entry.optInt("sdk_level", 29)));
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to load custom props database", e);
            }
        }
    }

    public Map<String, PropsEntry> getPropsDatabase() {
        return new LinkedHashMap<>(mPropsDatabase);
    }

    /**
     * Apply a props database entry to current config.
     */
    public void applyPropsEntry(String label) {
        PropsEntry entry = mPropsDatabase.get(label);
        if (entry != null) {
            mFingerprint = entry.fingerprint;
            mModel = entry.model;
            mManufacturer = entry.manufacturer;
            mProduct = entry.product;
            mDevice = entry.device;
            mBrand = entry.brand;
            mSecurityPatch = entry.securityPatch;
            mSdkLevel = entry.sdkLevel;
            saveConfig();
            Log.i(TAG, "Applied props entry: " + label);
        }
    }

    // ========== Auto-Fallback ==========

    public void tryFallback() {
        String[] slots = listKeyboxSlots();
        if (slots.length <= 1) {
            Log.w(TAG, "No fallback keybox available");
            return;
        }

        for (int i = 0; i < slots.length; i++) {
            if (slots[i].equals(mActiveKeyboxSlot)) {
                int nextIndex = (i + 1) % slots.length;
                mActiveKeyboxSlot = slots[nextIndex];
                saveConfig();
                Log.i(TAG, "Fallback to keybox slot: " + mActiveKeyboxSlot);
                KeyboxManager.getInstance().reload();
                return;
            }
        }
    }

    // ========== Data Classes ==========

    public static class PerAppConfig {
        public String packageName;
        public String fingerprint = "";
        public String model = "";
        public String manufacturer = "";
        public String product = "";
        public String device = "";
        public String brand = "";
        public boolean spoofingEnabled = true;

        public PerAppConfig(String packageName) {
            this.packageName = packageName;
        }
    }

    public static class PropsEntry {
        public String fingerprint;
        public String model;
        public String manufacturer;
        public String product;
        public String device;
        public String brand;
        public String securityPatch;
        public int sdkLevel;

        public PropsEntry(String fp, String model, String mfr,
                          String product, String device, String brand,
                          String secPatch, int sdk) {
            this.fingerprint = fp;
            this.model = model;
            this.manufacturer = mfr;
            this.product = product;
            this.device = device;
            this.brand = brand;
            this.securityPatch = secPatch;
            this.sdkLevel = sdk;
        }
    }
}
