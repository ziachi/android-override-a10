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
import java.util.List;
import java.util.regex.Pattern;

/**
 * Manages keybox loading for Keymaster HAL attestation.
 * Android 10 (API 29) version.
 *
 * Supports:
 * - Multiple Key elements (ECDSA + RSA) — uses first key found
 * - HTML comments embedded in PEM data (stripped automatically)
 * - Standard AndroidAttestation keybox XML format
 */
public class KeyboxManager {

    private static final String TAG = "KeyboxManager";
    private static final Pattern HTML_COMMENT = Pattern.compile("<!--.*?-->");

    private static volatile KeyboxManager sInstance;

    private PrivateKey mPrivateKey;
    private List<X509Certificate> mCertificateChain = new ArrayList<>();
    private String mKeyAlgorithm = "";
    private PrivateKey mSecondaryKey;
    private List<X509Certificate> mSecondaryCertChain = new ArrayList<>();
    private String mSecondaryAlgorithm = "";
    private boolean mLoaded = false;
    private long mLoadedTimestamp = 0;

    private boolean mRevoked = false;
    private int mFailureCount = 0;
    private static final int MAX_FAILURES = 3;
    private long mLastHealthCheck = 0;
    private static final long HEALTH_CHECK_INTERVAL = 3600000;

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

    public synchronized boolean load() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isKeyboxEnabled()) {
            Log.d(TAG, "Keybox disabled");
            return false;
        }

        String keyboxPath = controller.getActiveKeyboxPath();
        return loadFromFile(keyboxPath);
    }

    public synchronized void reload() {
        mLoaded = false;
        mPrivateKey = null;
        mCertificateChain.clear();
        mKeyAlgorithm = "";
        mRevoked = false;
        mFailureCount = 0;
        load();
    }

    private boolean loadFromFile(String path) {
        File file = new File(path);
        if (!file.exists()) {
            Log.w(TAG, "Keybox file not found: " + path);
            return false;
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(fis, "UTF-8");

            // Parse all <Key> elements — supports dual EC + RSA keybox
            List<KeyData> keyDataList = new ArrayList<>();
            KeyData currentKey = null;
            StringBuilder textBuilder = new StringBuilder();

            int eventType = parser.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                switch (eventType) {
                    case XmlPullParser.START_TAG:
                        textBuilder.setLength(0);
                        String startTag = parser.getName();

                        if ("Key".equals(startTag)) {
                            currentKey = new KeyData();
                            String algo = parser.getAttributeValue(null, "algorithm");
                            if (algo != null) {
                                currentKey.algorithm = algo.toUpperCase();
                            }
                        }
                        break;

                    case XmlPullParser.TEXT:
                        textBuilder.append(parser.getText());
                        break;

                    case XmlPullParser.END_TAG:
                        String endTag = parser.getName();
                        String text = textBuilder.toString().trim();

                        if ("Key".equals(endTag) && currentKey != null) {
                            keyDataList.add(currentKey);
                            currentKey = null;
                        } else if (currentKey != null) {
                            if ("PrivateKey".equals(endTag) && !text.isEmpty()) {
                                currentKey.privateKeyPem = stripHtmlComments(text);
                            } else if ("Certificate".equals(endTag) && !text.isEmpty()) {
                                currentKey.certPems.add(stripHtmlComments(text));
                            }
                        }
                        textBuilder.setLength(0);
                        break;
                }
                eventType = parser.next();
            }

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // Process first key → primary
            if (!keyDataList.isEmpty()) {
                KeyData first = keyDataList.get(0);
                if (first.privateKeyPem != null) {
                    mPrivateKey = parsePrivateKey(first.privateKeyPem);
                    mKeyAlgorithm = !first.algorithm.isEmpty() ? first.algorithm
                            : (mPrivateKey != null ? mPrivateKey.getAlgorithm().toUpperCase() : "");
                }
                mCertificateChain.clear();
                for (String certPem : first.certPems) {
                    mCertificateChain.add(parseCertificate(certFactory, certPem));
                }
            }

            // Process second key → secondary (if exists)
            if (keyDataList.size() >= 2) {
                KeyData second = keyDataList.get(1);
                if (second.privateKeyPem != null) {
                    mSecondaryKey = parsePrivateKey(second.privateKeyPem);
                    mSecondaryAlgorithm = !second.algorithm.isEmpty() ? second.algorithm
                            : (mSecondaryKey != null ? mSecondaryKey.getAlgorithm().toUpperCase() : "");
                }
                mSecondaryCertChain.clear();
                for (String certPem : second.certPems) {
                    mSecondaryCertChain.add(parseCertificate(certFactory, certPem));
                }
            }

            mLoaded = mPrivateKey != null && !mCertificateChain.isEmpty();
            mLoadedTimestamp = System.currentTimeMillis();

            if (mLoaded) {
                Log.i(TAG, "Keybox loaded: primary=" + mKeyAlgorithm
                        + " (" + mCertificateChain.size() + " certs)"
                        + (mSecondaryKey != null ?
                                ", secondary=" + mSecondaryAlgorithm
                                + " (" + mSecondaryCertChain.size() + " certs)" : "")
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
     * Strip HTML comments from PEM data.
     * Keybox files from some sources embed comments like
     * &lt;!--https://t.me/example--&gt; inside PEM blocks.
     */
    private X509Certificate parseCertificate(CertificateFactory factory, String pem) throws Exception {
        String cleaned = pem.trim();
        if (!cleaned.startsWith("-----BEGIN")) {
            cleaned = "-----BEGIN CERTIFICATE-----\n" + cleaned
                    + "\n-----END CERTIFICATE-----";
        }
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(cleaned.getBytes("UTF-8")));
    }

    /** Internal holder for parsed key data */
    private static class KeyData {
        String algorithm = "";
        String privateKeyPem;
        List<String> certPems = new ArrayList<>();
    }

        private String stripHtmlComments(String text) {
        return HTML_COMMENT.matcher(text).replaceAll("");
    }

    private PrivateKey parsePrivateKey(String pem) throws Exception {
        byte[] keyBytes;
        String algorithm;

        if (pem.contains("EC PRIVATE KEY")) {
            keyBytes = decodePem(pem, "EC PRIVATE KEY");
            algorithm = "EC";
        } else if (pem.contains("RSA PRIVATE KEY")) {
            keyBytes = decodePem(pem, "RSA PRIVATE KEY");
            algorithm = "RSA";
        } else if (pem.contains("PRIVATE KEY")) {
            keyBytes = decodePem(pem, "PRIVATE KEY");
            algorithm = "RSA";
        } else {
            keyBytes = decodeBase64(pem);
            algorithm = "RSA";
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        // Try specified algorithm first, then fallback
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            mKeyAlgorithm = algorithm;
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            String fallback = "EC".equals(algorithm) ? "RSA" : "EC";
            try {
                KeyFactory kf = KeyFactory.getInstance(fallback);
                mKeyAlgorithm = fallback;
                return kf.generatePrivate(spec);
            } catch (Exception e2) {
                throw new Exception("Failed to parse key as " + algorithm
                        + " or " + fallback, e2);
            }
        }
    }

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

    private byte[] decodeBase64(String base64) {
        String cleaned = base64.replaceAll("\\s+", "");
        return android.util.Base64.decode(cleaned, android.util.Base64.DEFAULT);
    }

    // ========== Getters ==========
    public boolean isLoaded() { return mLoaded; }
    public PrivateKey getPrivateKey() { return mPrivateKey; }
    public List<X509Certificate> getCertificateChain() {
        return new ArrayList<>(mCertificateChain);
    }
    public String getKeyAlgorithm() { return mKeyAlgorithm; }
    public long getLoadedTimestamp() { return mLoadedTimestamp; }

    // ========== Dual-Key Support (EC + RSA) ==========
    /**
     * Get private key by algorithm type.
     * Keybox XML may contain both EC and RSA keys.
     * @param algorithm "EC" or "RSA"
     * @return matching private key, or primary key if not found
     */
    public PrivateKey getPrivateKey(String algorithm) {
        if (algorithm != null) {
            if (algorithm.equalsIgnoreCase(mKeyAlgorithm) && mPrivateKey != null) {
                return mPrivateKey;
            }
            if (algorithm.equalsIgnoreCase(mSecondaryAlgorithm) && mSecondaryKey != null) {
                return mSecondaryKey;
            }
        }
        return mPrivateKey; // fallback to primary
    }

    /**
     * Get certificate chain by algorithm type.
     * @param algorithm "EC" or "RSA"
     * @return matching cert chain, or primary chain if not found
     */
    public List<X509Certificate> getCertificateChain(String algorithm) {
        if (algorithm != null) {
            if (algorithm.equalsIgnoreCase(mKeyAlgorithm) && !mCertificateChain.isEmpty()) {
                return new ArrayList<>(mCertificateChain);
            }
            if (algorithm.equalsIgnoreCase(mSecondaryAlgorithm) && !mSecondaryCertChain.isEmpty()) {
                return new ArrayList<>(mSecondaryCertChain);
            }
        }
        return new ArrayList<>(mCertificateChain); // fallback to primary
    }

    public boolean hasAlgorithm(String algorithm) {
        return algorithm.equalsIgnoreCase(mKeyAlgorithm)
                || algorithm.equalsIgnoreCase(mSecondaryAlgorithm);
    }

    public PrivateKey getSecondaryKey() { return mSecondaryKey; }
    public List<X509Certificate> getSecondaryCertChain() {
        return new ArrayList<>(mSecondaryCertChain);
    }
    public String getSecondaryAlgorithm() { return mSecondaryAlgorithm; }

    // ========== Health Monitoring ==========
    public synchronized KeyboxHealth checkHealth() {
        KeyboxHealth health = new KeyboxHealth();

        if (!mLoaded) {
            health.status = KeyboxHealth.STATUS_NOT_LOADED;
            health.message = "No keybox loaded";
            return health;
        }

        try {
            for (X509Certificate cert : mCertificateChain) {
                cert.checkValidity();
            }
            health.certValid = true;
        } catch (Exception e) {
            health.certValid = false;
            health.message = "Certificate expired: " + e.getMessage();
        }

        if (mFailureCount >= MAX_FAILURES) {
            health.status = KeyboxHealth.STATUS_LIKELY_REVOKED;
            health.message = "Multiple attestation failures — likely revoked";
            mRevoked = true;

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

    public void reportFailure() {
        mFailureCount++;
        Log.w(TAG, "Attestation failure reported, count=" + mFailureCount);
        if (mFailureCount >= MAX_FAILURES) {
            checkHealth();
        }
    }

    public void reportSuccess() {
        mFailureCount = 0;
        mRevoked = false;
    }

    public boolean isRevoked() { return mRevoked; }

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
