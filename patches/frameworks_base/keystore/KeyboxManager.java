/*
 * Copyright (C) 2025 Android Override Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.android.override;

import android.util.Log;
import android.util.Xml;

import org.xmlpull.v1.XmlPullParser;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Manages keybox loading for Keymaster HAL attestation.
 * Android 10 (API 29) version.
 *
 * Key differences from Android 13+ (KeyMint) version:
 * - Uses Keymaster 4.x HAL interface (not KeyMint 1.0+)
 * - Keybox format may differ slightly (RSA vs EC)
 * - Certificate chain handling for older format
 * - No attestation ID provisioning (A10 uses legacy method)
 *
 * Loads user-provided keybox XML files containing:
 * - Private key (PEM-encoded RSA or EC)
 * - Certificate chain (PEM-encoded X.509)
 *
 * Supports multiple named slots with auto-fallback.
 */
public class KeyboxManager {

    private static final String TAG = "KeyboxManager";

    private static volatile KeyboxManager sInstance;

    // Loaded keybox data
    private PrivateKey mPrivateKey;
    private List<X509Certificate> mCertificateChain = new ArrayList<>();
    private String mKeyAlgorithm = ""; // RSA or EC
    private boolean mLoaded = false;
    private long mLoadedTimestamp = 0;

    // Health monitoring
    private boolean mRevoked = false;
    private int mFailureCount = 0;
    private static final int MAX_FAILURES = 3;
    private long mLastHealthCheck = 0;
    private static final long HEALTH_CHECK_INTERVAL = 3600000; // 1 hour

    private KeyboxManager() {}

    public static KeyboxManager getInstance() {
        if (sInstance == null) {
            synchronized (KeyboxManager.class) {
                if (sInstance == null) {
                    sInstance = new KeyboxManager();
                }
            }
        }
        return sInstance;
    }

    /**
     * Load keybox from current active slot.
     */
    public synchronized boolean load() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isKeyboxEnabled()) {
            Log.d(TAG, "Keybox disabled");
            return false;
        }

        String keyboxPath = controller.getActiveKeyboxPath();
        return loadFromFile(keyboxPath);
    }

    /**
     * Reload keybox (used after slot change / fallback).
     */
    public synchronized void reload() {
        mLoaded = false;
        mPrivateKey = null;
        mCertificateChain.clear();
        mKeyAlgorithm = "";
        mRevoked = false;
        mFailureCount = 0;
        load();
    }

    /**
     * Load keybox from a specific file.
     */
    private boolean loadFromFile(String path) {
        File file = new File(path);
        if (!file.exists()) {
            Log.w(TAG, "Keybox file not found: " + path);
            return false;
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(fis, "UTF-8");

            String privateKeyPem = null;
            List<String> certPems = new ArrayList<>();
            String currentTag = "";
            StringBuilder textBuilder = new StringBuilder();

            int eventType = parser.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                switch (eventType) {
                    case XmlPullParser.START_TAG:
                        currentTag = parser.getName();
                        textBuilder.setLength(0);

                        // Check algorithm attribute
                        if ("Keybox".equals(currentTag)) {
                            String algo = parser.getAttributeValue(null, "algorithm");
                            if (algo != null) {
                                mKeyAlgorithm = algo.toUpperCase();
                            }
                        }
                        break;

                    case XmlPullParser.TEXT:
                        textBuilder.append(parser.getText());
                        break;

                    case XmlPullParser.END_TAG:
                        String text = textBuilder.toString().trim();
                        if ("PrivateKey".equals(parser.getName()) && !text.isEmpty()) {
                            privateKeyPem = text;
                        } else if ("Certificate".equals(parser.getName()) && !text.isEmpty()) {
                            certPems.add(text);
                        }
                        currentTag = "";
                        break;
                }
                eventType = parser.next();
            }

            // Parse private key
            if (privateKeyPem != null) {
                mPrivateKey = parsePrivateKey(privateKeyPem);
            }

            // Parse certificate chain
            mCertificateChain.clear();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            for (String certPem : certPems) {
                byte[] certBytes = decodePem(certPem, "CERTIFICATE");
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(certBytes));
                mCertificateChain.add(cert);
            }

            // Auto-detect algorithm if not specified
            if (mKeyAlgorithm.isEmpty() && mPrivateKey != null) {
                mKeyAlgorithm = mPrivateKey.getAlgorithm().toUpperCase();
            }

            mLoaded = mPrivateKey != null && !mCertificateChain.isEmpty();
            mLoadedTimestamp = System.currentTimeMillis();

            if (mLoaded) {
                Log.i(TAG, "Keybox loaded: algo=" + mKeyAlgorithm
                        + " certs=" + mCertificateChain.size()
                        + " slot=" + OverrideController.getInstance().getActiveKeyboxSlot());
            } else {
                Log.e(TAG, "Keybox incomplete: key=" + (mPrivateKey != null)
                        + " certs=" + mCertificateChain.size());
            }

            return mLoaded;
        } catch (Exception e) {
            Log.e(TAG, "Failed to load keybox: " + path, e);
            return false;
        }
    }

    /**
     * Parse PEM-encoded private key (RSA or EC).
     */
    private PrivateKey parsePrivateKey(String pem) throws Exception {
        byte[] keyBytes;
        String algorithm;

        if (pem.contains("RSA PRIVATE KEY") || pem.contains("PRIVATE KEY")) {
            // Try RSA first (most common for Keymaster)
            if (pem.contains("EC PRIVATE KEY")) {
                keyBytes = decodePem(pem, "EC PRIVATE KEY");
                algorithm = "EC";
            } else if (pem.contains("RSA PRIVATE KEY")) {
                keyBytes = decodePem(pem, "RSA PRIVATE KEY");
                algorithm = "RSA";
            } else {
                keyBytes = decodePem(pem, "PRIVATE KEY");
                // PKCS#8 format — algorithm determined by key
                algorithm = "RSA"; // default, will be corrected by KeyFactory
            }
        } else {
            // Raw base64, assume RSA
            keyBytes = decodeBase64(pem);
            algorithm = "RSA";
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        // Try RSA first, then EC
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            mKeyAlgorithm = "RSA";
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            try {
                KeyFactory kf = KeyFactory.getInstance("EC");
                mKeyAlgorithm = "EC";
                return kf.generatePrivate(spec);
            } catch (Exception e2) {
                throw new Exception("Failed to parse private key as RSA or EC", e2);
            }
        }
    }

    /**
     * Decode PEM-encoded data.
     */
    private byte[] decodePem(String pem, String type) {
        String header = "-----BEGIN " + type + "-----";
        String footer = "-----END " + type + "-----";

        String base64 = pem;
        int headerIdx = pem.indexOf(header);
        if (headerIdx >= 0) {
            int footerIdx = pem.indexOf(footer);
            if (footerIdx > headerIdx) {
                base64 = pem.substring(headerIdx + header.length(), footerIdx);
            }
        }

        return decodeBase64(base64);
    }

    /**
     * Decode base64 string.
     */
    private byte[] decodeBase64(String base64) {
        String cleaned = base64.replaceAll("\\s+", "");
        // Use android.util.Base64 for Android 10 compatibility
        return android.util.Base64.decode(cleaned, android.util.Base64.DEFAULT);
    }

    // ========== Getters ==========

    public boolean isLoaded() { return mLoaded; }
    public PrivateKey getPrivateKey() { return mPrivateKey; }
    public List<X509Certificate> getCertificateChain() { return new ArrayList<>(mCertificateChain); }
    public String getKeyAlgorithm() { return mKeyAlgorithm; }
    public long getLoadedTimestamp() { return mLoadedTimestamp; }

    // ========== Health Monitoring ==========

    /**
     * Check keybox health — detect revocation.
     */
    public synchronized KeyboxHealth checkHealth() {
        KeyboxHealth health = new KeyboxHealth();

        if (!mLoaded) {
            health.status = KeyboxHealth.STATUS_NOT_LOADED;
            health.message = "No keybox loaded";
            return health;
        }

        // Check certificate validity
        try {
            for (X509Certificate cert : mCertificateChain) {
                cert.checkValidity();
            }
            health.certValid = true;
        } catch (Exception e) {
            health.certValid = false;
            health.message = "Certificate expired: " + e.getMessage();
        }

        // Check failure count
        if (mFailureCount >= MAX_FAILURES) {
            health.status = KeyboxHealth.STATUS_LIKELY_REVOKED;
            health.message = "Multiple attestation failures — likely revoked";
            mRevoked = true;

            // Auto-fallback if enabled
            OverrideController controller = OverrideController.getInstance();
            if (controller.isAutoFallbackEnabled()) {
                controller.tryFallback();
                health.message += " (auto-fallback triggered)";
            }
        } else if (health.certValid) {
            health.status = KeyboxHealth.STATUS_OK;
            health.message = "Keybox healthy";
        } else {
            health.status = KeyboxHealth.STATUS_DEGRADED;
        }

        health.algorithm = mKeyAlgorithm;
        health.certCount = mCertificateChain.size();
        health.failureCount = mFailureCount;
        health.slot = OverrideController.getInstance().getActiveKeyboxSlot();

        mLastHealthCheck = System.currentTimeMillis();
        return health;
    }

    /**
     * Report attestation failure (called by AttestationHooks).
     */
    public void reportFailure() {
        mFailureCount++;
        Log.w(TAG, "Attestation failure reported, count=" + mFailureCount);

        if (mFailureCount >= MAX_FAILURES) {
            checkHealth(); // Triggers auto-fallback
        }
    }

    /**
     * Report attestation success (resets failure count).
     */
    public void reportSuccess() {
        mFailureCount = 0;
        mRevoked = false;
    }

    public boolean isRevoked() { return mRevoked; }

    /**
     * Keybox health status.
     */
    public static class KeyboxHealth {
        public static final int STATUS_OK = 0;
        public static final int STATUS_NOT_LOADED = 1;
        public static final int STATUS_DEGRADED = 2;
        public static final int STATUS_LIKELY_REVOKED = 3;

        public int status = STATUS_NOT_LOADED;
        public String message = "";
        public boolean certValid = false;
        public String algorithm = "";
        public int certCount = 0;
        public int failureCount = 0;
        public String slot = "";
    }
}
