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
import java.io.ByteArrayOutputStream;
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
 * - SEC1 EC and PKCS#1 RSA key formats (auto-converted to PKCS#8)
 * - Standard AndroidAttestation keybox XML format
 */
public class KeyboxManager {

    private static final String TAG = "KeyboxManager";
    private static final Pattern HTML_COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);

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

        try {
            // Read file as string and strip HTML comments BEFORE XML parsing
            FileInputStream fis = new FileInputStream(file);
            byte[] fileBytes = new byte[(int) file.length()];
            fis.read(fileBytes);
            fis.close();
            String xmlContent = new String(fileBytes, "UTF-8");

            // Strip all HTML comments (they break XmlPullParser)
            xmlContent = HTML_COMMENT.matcher(xmlContent).replaceAll("");
            Log.d(TAG, "Keybox XML size=" + xmlContent.length()
                    + " hasKey=" + xmlContent.contains("<Key")
                    + " hasPrivateKey=" + xmlContent.contains("PRIVATE KEY"));

            // Parse cleaned XML
            ByteArrayInputStream bis = new ByteArrayInputStream(xmlContent.getBytes("UTF-8"));
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(bis, "UTF-8");

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
                                currentKey.privateKeyPem = text;
                            } else if ("Certificate".equals(endTag) && !text.isEmpty()) {
                                currentKey.certPems.add(text);
                            }
                        }
                        textBuilder.setLength(0);
                        break;
                }
                eventType = parser.next();
            }

            Log.d(TAG, "Parsed " + keyDataList.size() + " key(s) from keybox");

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // Process first key → primary
            if (!keyDataList.isEmpty()) {
                KeyData first = keyDataList.get(0);
                if (first.privateKeyPem != null) {
                    Log.d(TAG, "Parsing primary key, algo=" + first.algorithm
                            + " pem_len=" + first.privateKeyPem.length());
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
                    Log.d(TAG, "Parsing secondary key, algo=" + second.algorithm
                            + " pem_len=" + second.privateKeyPem.length());
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

    // ========== Key Parsing (SEC1/PKCS#1/PKCS#8) ==========

    private PrivateKey parsePrivateKey(String pem) throws Exception {
        byte[] keyBytes;
        String format;

        if (pem.contains("EC PRIVATE KEY")) {
            // SEC1 format → needs PKCS#8 wrapping
            keyBytes = decodePem(pem, "EC PRIVATE KEY");
            Log.d(TAG, "EC key (SEC1 format), raw_len=" + keyBytes.length);
            keyBytes = wrapEcKeyInPkcs8(keyBytes);
            format = "EC";
        } else if (pem.contains("RSA PRIVATE KEY")) {
            // PKCS#1 format → needs PKCS#8 wrapping
            keyBytes = decodePem(pem, "RSA PRIVATE KEY");
            Log.d(TAG, "RSA key (PKCS#1 format), raw_len=" + keyBytes.length);
            keyBytes = wrapRsaKeyInPkcs8(keyBytes);
            format = "RSA";
        } else if (pem.contains("PRIVATE KEY")) {
            // Already PKCS#8 format
            keyBytes = decodePem(pem, "PRIVATE KEY");
            Log.d(TAG, "Key (PKCS#8 format), raw_len=" + keyBytes.length);
            format = "RSA"; // will try both
        } else {
            keyBytes = decodeBase64(pem);
            format = "RSA";
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        Log.d(TAG, "PKCS#8 spec created, len=" + keyBytes.length);

        // Try specified algorithm first, then fallback
        // NOTE: do NOT modify mKeyAlgorithm here — caller handles it
        try {
            KeyFactory kf = KeyFactory.getInstance(format);
            PrivateKey key = kf.generatePrivate(spec);
            Log.i(TAG, "Key parsed OK as " + format);
            return key;
        } catch (Exception e) {
            Log.w(TAG, "Failed as " + format + ": " + e.getMessage());
            String fallback = "EC".equals(format) ? "RSA" : "EC";
            try {
                KeyFactory kf = KeyFactory.getInstance(fallback);
                PrivateKey key = kf.generatePrivate(spec);
                Log.i(TAG, "Key parsed OK as " + fallback + " (fallback)");
                return key;
            } catch (Exception e2) {
                throw new Exception("Failed to parse key as " + format
                        + " or " + fallback, e2);
            }
        }
    }

    /**
     * Wrap SEC1 EC private key DER bytes in PKCS#8 envelope.
     * SEC1 format: SEQUENCE { version, privateKey, [0] curveOID, [1] publicKey }
     * PKCS#8: SEQUENCE { version, AlgorithmIdentifier { ecOID, curveOID }, OCTET STRING { SEC1 } }
     */
    private byte[] wrapEcKeyInPkcs8(byte[] sec1Der) throws Exception {
        // Extract curve OID from SEC1 [0] tag, or default to P-256
        byte[] curveOidBytes = extractCurveOidFromSec1(sec1Der);
        if (curveOidBytes == null) {
            // P-256 / secp256r1 / prime256v1: OID 1.2.840.10045.3.1.7
            curveOidBytes = new byte[] {
                0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01, 0x07
            };
            Log.d(TAG, "No curve OID in SEC1, defaulting to P-256");
        }

        // ecPublicKey OID: 1.2.840.10045.2.1
        byte[] ecOid = { 0x06, 0x07, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01 };

        byte[] algoId = asn1Sequence(concat(ecOid, curveOidBytes));
        byte[] version = { 0x02, 0x01, 0x00 };
        byte[] keyOctet = asn1OctetString(sec1Der);

        return asn1Sequence(concat(version, algoId, keyOctet));
    }

    /**
     * Wrap PKCS#1 RSA private key DER bytes in PKCS#8 envelope.
     * PKCS#1: SEQUENCE { version, modulus, publicExponent, ... }
     * PKCS#8: SEQUENCE { version, AlgorithmIdentifier { rsaOID, NULL }, OCTET STRING { PKCS#1 } }
     */
    private byte[] wrapRsaKeyInPkcs8(byte[] pkcs1Der) throws Exception {
        // rsaEncryption OID: 1.2.840.113549.1.1.1
        byte[] rsaOid = {
            0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01
        };
        byte[] nullVal = { 0x05, 0x00 };

        byte[] algoId = asn1Sequence(concat(rsaOid, nullVal));
        byte[] version = { 0x02, 0x01, 0x00 };
        byte[] keyOctet = asn1OctetString(pkcs1Der);

        return asn1Sequence(concat(version, algoId, keyOctet));
    }

    /**
     * Extract curve OID from SEC1 ECPrivateKey structure.
     * Looks for the [0] EXPLICIT tag containing the curve OID.
     */
    private byte[] extractCurveOidFromSec1(byte[] der) {
        try {
            if (der.length < 2 || der[0] != 0x30) return null;

            int offset = 2;
            if ((der[1] & 0x80) != 0) {
                int lenBytes = der[1] & 0x7F;
                offset = 2 + lenBytes;
            }

            // Walk through the SEQUENCE looking for tag 0xA0 (context [0])
            while (offset < der.length - 2) {
                int tag = der[offset] & 0xFF;
                int len = der[offset + 1] & 0xFF;
                int headerSize = 2;

                if ((len & 0x80) != 0) {
                    int lenBytes = len & 0x7F;
                    len = 0;
                    for (int i = 0; i < lenBytes; i++) {
                        len = (len << 8) | (der[offset + 2 + i] & 0xFF);
                    }
                    headerSize = 2 + lenBytes;
                }

                if (tag == 0xA0) {
                    // Found [0] — contains the curve OID
                    int oidStart = offset + headerSize;
                    if (oidStart < der.length && der[oidStart] == 0x06) {
                        int oidLen = der[oidStart + 1] & 0xFF;
                        byte[] oid = new byte[oidLen + 2];
                        System.arraycopy(der, oidStart, oid, 0, oid.length);
                        Log.d(TAG, "Extracted curve OID, len=" + oid.length);
                        return oid;
                    }
                }

                offset += headerSize + len;
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to extract curve OID: " + e.getMessage());
        }
        return null;
    }

    // ========== ASN.1 DER Helpers ==========

    private byte[] asn1Sequence(byte[] content) {
        return asn1Wrap((byte) 0x30, content);
    }

    private byte[] asn1OctetString(byte[] content) {
        return asn1Wrap((byte) 0x04, content);
    }

    private byte[] asn1Wrap(byte tag, byte[] content) {
        byte[] lenBytes = asn1Length(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    private byte[] asn1Length(int length) {
        if (length < 128) {
            return new byte[] { (byte) length };
        } else if (length < 256) {
            return new byte[] { (byte) 0x81, (byte) length };
        } else if (length < 65536) {
            return new byte[] { (byte) 0x82, (byte) (length >> 8), (byte) (length & 0xFF) };
        } else {
            return new byte[] { (byte) 0x83,
                (byte) (length >> 16), (byte) ((length >> 8) & 0xFF), (byte) (length & 0xFF) };
        }
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, offset, a.length);
            offset += a.length;
        }
        return result;
    }

    // ========== PEM/Certificate Helpers ==========

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
    public PrivateKey getPrivateKey(String algorithm) {
        if (algorithm != null) {
            if (algorithm.equalsIgnoreCase(mKeyAlgorithm) && mPrivateKey != null) {
                return mPrivateKey;
            }
            if (algorithm.equalsIgnoreCase(mSecondaryAlgorithm) && mSecondaryKey != null) {
                return mSecondaryKey;
            }
        }
        return mPrivateKey;
    }

    public List<X509Certificate> getCertificateChain(String algorithm) {
        if (algorithm != null) {
            if (algorithm.equalsIgnoreCase(mKeyAlgorithm) && !mCertificateChain.isEmpty()) {
                return new ArrayList<>(mCertificateChain);
            }
            if (algorithm.equalsIgnoreCase(mSecondaryAlgorithm) && !mSecondaryCertChain.isEmpty()) {
                return new ArrayList<>(mSecondaryCertChain);
            }
        }
        return new ArrayList<>(mCertificateChain);
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
