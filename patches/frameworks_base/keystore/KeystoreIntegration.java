/*
 * Copyright (C) 2025 Android Override Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.android.override;

import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Keystore attestation integration for Android 10.
 *
 * Bridges AttestationHooks/KeyboxManager into the actual keystore
 * attestation flow. When GMS requests key attestation, this class
 * generates a spoofed attestation certificate chain using the
 * imported keybox.
 *
 * Flow:
 * 1. GMS calls KeyPairGenerator with attestation challenge
 * 2. Framework calls android.security.KeyStore.generateKey()
 * 3. After real key generation, we intercept attestKey()
 * 4. Build spoofed leaf cert with challenge + public key
 * 5. Sign with imported keybox private key
 * 6. Return [leaf, intermediate(s), root] from keybox
 *
 * Attestation Extension OID: 1.3.6.1.4.1.11129.2.1.17
 *
 * For hardware attestation (Device Integrity PASS):
 * - SecurityLevel must be TrustedEnvironment (1) or StrongBox (2)
 * - Verified boot state must be Verified (0)
 * - Device must appear locked
 * - Cert chain must be rooted in Google's attestation root CA
 *
 * ASN.1 AuthorizationList tag reference (Keymaster v4):
 *   [1]   purpose          SET OF INTEGER
 *   [2]   algorithm        INTEGER          (EC=3, RSA=1)
 *   [3]   keySize          INTEGER          (256, 2048, etc.)
 *   [5]   digest           SET OF INTEGER   (SHA256=4)
 *   [6]   padding          SET OF INTEGER
 *   [10]  ecCurve          INTEGER          (P256=1)
 *   [200] origin           INTEGER          (Generated=0)
 *   [303] rootOfTrust      SEQUENCE         (KM_TAG_ROOT_OF_TRUST → tag 704 in attestation)
 *   [701] creationDateTime INTEGER
 *   [704] rootOfTrust      RootOfTrust SEQUENCE
 *   [705] osVersion        INTEGER
 *   [706] osPatchLevel     INTEGER
 *   [709] attestationApplicationId  OCTET STRING
 */
public class KeystoreIntegration {

    private static final String TAG = "KeystoreIntegration";

    // Attestation extension OID
    private static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";

    // Keymaster versions
    private static final int KEYMASTER_VERSION = 4;  // Keymaster 4.x for A10
    private static final int ATTESTATION_VERSION = 3; // Attestation v3 for Keymaster 4

    // Keymaster algorithm constants
    private static final int KM_ALGORITHM_RSA = 1;
    private static final int KM_ALGORITHM_EC = 3;

    // Keymaster digest constants
    private static final int KM_DIGEST_SHA256 = 4;

    // Keymaster purpose constants
    private static final int KM_PURPOSE_SIGN = 2;

    // Keymaster EC curve constants
    private static final int KM_EC_CURVE_P256 = 1;

    // Keymaster origin constants
    private static final int KM_ORIGIN_GENERATED = 0;

    /**
     * Check if we should intercept attestation for this process.
     */
    public static boolean shouldInterceptAttestation() {
        OverrideController controller = OverrideController.getInstance();
        if (!controller.isEnabled() || !controller.isSpoofAttestationEnabled()) {
            return false;
        }

        KeyboxManager keybox = KeyboxManager.getInstance();
        if (!keybox.isLoaded()) {
            keybox.load();
        }

        return keybox.isLoaded() && !keybox.isRevoked();
    }

    /**
     * Generate spoofed attestation certificate chain.
     *
     * @param publicKeyToAttest The public key being attested
     * @param challenge The attestation challenge from the caller
     * @param applicationId The calling application package info
     * @param isStrongBox Whether StrongBox was requested
     * @return Spoofed certificate chain as byte arrays, or null to use real chain
     */
    public static List<byte[]> generateSpoofedAttestationChain(
            PublicKey publicKeyToAttest,
            byte[] challenge,
            byte[] applicationId,
            boolean isStrongBox) {

        if (!shouldInterceptAttestation()) {
            return null;
        }

        try {
            KeyboxManager keybox = KeyboxManager.getInstance();
            PrivateKey signingKey = keybox.getPrivateKey();
            List<X509Certificate> keyboxChain = keybox.getCertificateChain();
            String signingAlgorithm = keybox.getKeyAlgorithm();

            if (signingKey == null || keyboxChain.isEmpty()) {
                Log.e(TAG, "Keybox not ready: key=" + (signingKey != null)
                        + " chain=" + keyboxChain.size());
                keybox.reportFailure();
                return null;
            }

            // Detect the attested key type
            KeyInfo attestedKeyInfo = detectKeyType(publicKeyToAttest);
            Log.d(TAG, "Attested key: algo=" + attestedKeyInfo.algorithmName
                    + " size=" + attestedKeyInfo.keySize
                    + ", Signing key: algo=" + signingAlgorithm);

            // Build the leaf attestation certificate
            byte[] leafCertBytes = buildAttestationLeafCert(
                    publicKeyToAttest,
                    signingKey,
                    keyboxChain.get(0), // issuer cert
                    challenge,
                    applicationId,
                    signingAlgorithm,
                    attestedKeyInfo,
                    isStrongBox);

            if (leafCertBytes == null) {
                Log.e(TAG, "Failed to build leaf cert");
                keybox.reportFailure();
                return null;
            }

            // Assemble the full chain: [leaf, ...keybox chain]
            List<byte[]> chain = new ArrayList<>();
            chain.add(leafCertBytes);
            for (X509Certificate cert : keyboxChain) {
                chain.add(cert.getEncoded());
            }

            Log.i(TAG, "Attestation chain generated: " + chain.size()
                    + " certs, signing=" + signingAlgorithm
                    + ", attested=" + attestedKeyInfo.algorithmName
                    + "/" + attestedKeyInfo.keySize
                    + ", challenge=" + challenge.length + " bytes");

            keybox.reportSuccess();
            return chain;

        } catch (Exception e) {
            Log.e(TAG, "Failed to generate spoofed attestation", e);
            KeyboxManager.getInstance().reportFailure();
            return null;
        }
    }

    /**
     * Detect key type and size from a PublicKey instance.
     */
    private static KeyInfo detectKeyType(PublicKey key) {
        if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) key;
            int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
            return new KeyInfo(KM_ALGORITHM_EC, "EC", fieldSize,
                    fieldSize == 256 ? KM_EC_CURVE_P256 : KM_EC_CURVE_P256);
        } else if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) key;
            int keySize = rsaKey.getModulus().bitLength();
            return new KeyInfo(KM_ALGORITHM_RSA, "RSA", keySize, -1);
        }
        // Fallback: try to determine from key algorithm name
        String algo = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algo)) {
            return new KeyInfo(KM_ALGORITHM_RSA, "RSA", 2048, -1);
        }
        // Default to EC P-256
        return new KeyInfo(KM_ALGORITHM_EC, "EC", 256, KM_EC_CURVE_P256);
    }

    /**
     * Build the leaf attestation certificate.
     *
     * The leaf cert contains:
     * - Subject public key = the key being attested
     * - Issuer = keybox intermediate CA
     * - Attestation extension with challenge, security level, etc.
     * - Signed by keybox private key
     */
    private static byte[] buildAttestationLeafCert(
            PublicKey subjectKey,
            PrivateKey signingKey,
            X509Certificate issuerCert,
            byte[] challenge,
            byte[] applicationId,
            String signingAlgorithm,
            KeyInfo attestedKeyInfo,
            boolean isStrongBox) throws Exception {

        // Build attestation extension with correct key info
        byte[] attestationExtension = buildAttestationExtension(
                challenge, applicationId, attestedKeyInfo, isStrongBox);

        // Build TBS (To-Be-Signed) certificate structure
        byte[] tbsCert = buildTBSCertificate(
                subjectKey,
                issuerCert,
                attestationExtension,
                signingAlgorithm);

        // Sign with keybox private key
        String sigAlgo = "EC".equals(signingAlgorithm) ?
                "SHA256withECDSA" : "SHA256withRSA";
        Signature sig = Signature.getInstance(sigAlgo);
        sig.initSign(signingKey);
        sig.update(tbsCert);
        byte[] signature = sig.sign();

        // Wrap in X.509 Certificate structure
        return buildX509Certificate(tbsCert, signature, signingAlgorithm);
    }

    /**
     * Build KeyDescription attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
     *
     * ASN.1 structure (Keymaster v4):
     * KeyDescription ::= SEQUENCE {
     *     attestationVersion     INTEGER,     -- 3 for KM4
     *     attestationSecurityLevel SecurityLevel,
     *     keymasterVersion       INTEGER,     -- 4
     *     keymasterSecurityLevel SecurityLevel,
     *     attestationChallenge   OCTET STRING,
     *     uniqueId               OCTET STRING,
     *     softwareEnforced       AuthorizationList,
     *     teeEnforced            AuthorizationList
     * }
     *
     * SecurityLevel: Software(0), TrustedEnvironment(1), StrongBox(2)
     */
    private static byte[] buildAttestationExtension(
            byte[] challenge,
            byte[] applicationId,
            KeyInfo attestedKeyInfo,
            boolean isStrongBox) throws Exception {

        int securityLevel = isStrongBox ?
                AttestationHooks.SECURITY_LEVEL_STRONGBOX :
                AttestationHooks.getSpoofedSecurityLevel();

        AttestationHooks.RootOfTrust rot = AttestationHooks.getSpoofedRootOfTrust();

        ByteArrayOutputStream ext = new ByteArrayOutputStream();

        // Build the inner SEQUENCE content
        ByteArrayOutputStream seqContent = new ByteArrayOutputStream();

        // attestationVersion INTEGER (3)
        seqContent.write(asn1Integer(ATTESTATION_VERSION));

        // attestationSecurityLevel ENUM
        seqContent.write(asn1Enum(securityLevel));

        // keymasterVersion INTEGER (4)
        seqContent.write(asn1Integer(KEYMASTER_VERSION));

        // keymasterSecurityLevel ENUM
        seqContent.write(asn1Enum(securityLevel));

        // attestationChallenge OCTET STRING
        seqContent.write(asn1OctetString(challenge));

        // uniqueId OCTET STRING (empty)
        seqContent.write(asn1OctetString(new byte[0]));

        // softwareEnforced AuthorizationList (minimal)
        seqContent.write(buildSoftwareEnforcedAuthList(applicationId));

        // teeEnforced AuthorizationList (with RootOfTrust + correct key info)
        seqContent.write(buildTeeEnforcedAuthList(rot, attestedKeyInfo));

        // Wrap in SEQUENCE
        byte[] seqBytes = seqContent.toByteArray();
        ext.write(0x30); // SEQUENCE tag
        ext.write(asn1Length(seqBytes.length));
        ext.write(seqBytes);

        return ext.toByteArray();
    }

    /**
     * Build softwareEnforced AuthorizationList.
     *
     * Minimal set — most enforcement is in TEE.
     * Contains: creationDateTime, attestationApplicationId
     */
    private static byte[] buildSoftwareEnforcedAuthList(byte[] applicationId) throws Exception {
        ByteArrayOutputStream content = new ByteArrayOutputStream();

        // Tag 701 = creationDateTime [CONTEXT 701]
        long now = System.currentTimeMillis();
        byte[] dateTag = asn1ExplicitTag(701, asn1Integer(now));
        content.write(dateTag);

        // Tag 709 = attestationApplicationId [CONTEXT 709]
        if (applicationId != null && applicationId.length > 0) {
            byte[] appIdTag = asn1ExplicitTag(709, asn1OctetString(applicationId));
            content.write(appIdTag);
        }

        byte[] contentBytes = content.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x30); // SEQUENCE
        result.write(asn1Length(contentBytes.length));
        result.write(contentBytes);
        return result.toByteArray();
    }

    /**
     * Build teeEnforced AuthorizationList.
     *
     * Contains RootOfTrust, purpose, algorithm, key size, digest, etc.
     * This is the critical part for hardware attestation.
     *
     * Tag reference (Keymaster attestation ASN.1):
     *   [1]   purpose     SET OF INTEGER
     *   [2]   algorithm   INTEGER          ← was WRONG (used [5])
     *   [3]   keySize     INTEGER          ← was WRONG (used [6])
     *   [5]   digest      SET OF INTEGER
     *   [6]   padding     SET OF INTEGER
     *   [10]  ecCurve     INTEGER          (only for EC keys)
     *   [200] origin      INTEGER
     *   [704] rootOfTrust RootOfTrust SEQUENCE
     *   [705] osVersion   INTEGER
     *   [706] osPatchLevel INTEGER
     */
    private static byte[] buildTeeEnforcedAuthList(
            AttestationHooks.RootOfTrust rot,
            KeyInfo keyInfo) throws Exception {
        ByteArrayOutputStream content = new ByteArrayOutputStream();

        // [1] purpose SET {sign(2)}
        ByteArrayOutputStream purposeSet = new ByteArrayOutputStream();
        purposeSet.write(asn1Integer(KM_PURPOSE_SIGN));
        byte[] purposeSetBytes = purposeSet.toByteArray();
        ByteArrayOutputStream purposeSetWrapper = new ByteArrayOutputStream();
        purposeSetWrapper.write(0x31); // SET
        purposeSetWrapper.write(asn1Length(purposeSetBytes.length));
        purposeSetWrapper.write(purposeSetBytes);
        content.write(asn1ExplicitTag(1, purposeSetWrapper.toByteArray()));

        // [2] algorithm INTEGER — FIXED: was using tag [5]
        content.write(asn1ExplicitTag(2, asn1Integer(keyInfo.algorithm)));

        // [3] keySize INTEGER — FIXED: was using tag [6]
        content.write(asn1ExplicitTag(3, asn1Integer(keyInfo.keySize)));

        // [5] digest SET {SHA256(4)}
        ByteArrayOutputStream digestSet = new ByteArrayOutputStream();
        digestSet.write(asn1Integer(KM_DIGEST_SHA256));
        byte[] digestSetBytes = digestSet.toByteArray();
        ByteArrayOutputStream digestSetWrapper = new ByteArrayOutputStream();
        digestSetWrapper.write(0x31); // SET
        digestSetWrapper.write(asn1Length(digestSetBytes.length));
        digestSetWrapper.write(digestSetBytes);
        content.write(asn1ExplicitTag(5, digestSetWrapper.toByteArray()));

        // [6] padding SET — only for RSA keys
        if (keyInfo.algorithm == KM_ALGORITHM_RSA) {
            // PSS(1) for signing
            ByteArrayOutputStream paddingSet = new ByteArrayOutputStream();
            paddingSet.write(asn1Integer(1)); // KM_PAD_RSA_PSS
            byte[] paddingSetBytes = paddingSet.toByteArray();
            ByteArrayOutputStream paddingSetWrapper = new ByteArrayOutputStream();
            paddingSetWrapper.write(0x31); // SET
            paddingSetWrapper.write(asn1Length(paddingSetBytes.length));
            paddingSetWrapper.write(paddingSetBytes);
            content.write(asn1ExplicitTag(6, paddingSetWrapper.toByteArray()));
        }

        // [10] ecCurve INTEGER — only for EC keys
        if (keyInfo.algorithm == KM_ALGORITHM_EC && keyInfo.ecCurve > 0) {
            content.write(asn1ExplicitTag(10, asn1Integer(keyInfo.ecCurve)));
        }

        // [200] origin INTEGER (Generated = 0)
        content.write(asn1ExplicitTag(200, asn1Integer(KM_ORIGIN_GENERATED)));

        // [704] rootOfTrust SEQUENCE
        if (rot != null) {
            ByteArrayOutputStream rotSeq = new ByteArrayOutputStream();
            // verifiedBootKey OCTET STRING
            rotSeq.write(asn1OctetString(rot.verifiedBootKey));
            // deviceLocked BOOLEAN
            rotSeq.write(asn1Boolean(rot.deviceLocked));
            // verifiedBootState ENUM
            rotSeq.write(asn1Enum(rot.verifiedBootState));
            // verifiedBootHash OCTET STRING (KM4+)
            if (rot.verifiedBootHash != null) {
                rotSeq.write(asn1OctetString(rot.verifiedBootHash));
            }
            byte[] rotSeqBytes = rotSeq.toByteArray();
            ByteArrayOutputStream rotWrapper = new ByteArrayOutputStream();
            rotWrapper.write(0x30); // SEQUENCE
            rotWrapper.write(asn1Length(rotSeqBytes.length));
            rotWrapper.write(rotSeqBytes);
            content.write(asn1ExplicitTag(704, rotWrapper.toByteArray()));
        }

        // [705] osVersion INTEGER
        content.write(asn1ExplicitTag(705,
                asn1Integer(AttestationHooks.getSpoofedOsVersion())));

        // [706] osPatchLevel INTEGER
        content.write(asn1ExplicitTag(706,
                asn1Integer(AttestationHooks.getSpoofedOsPatchLevel())));

        byte[] contentBytes = content.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x30); // SEQUENCE
        result.write(asn1Length(contentBytes.length));
        result.write(contentBytes);
        return result.toByteArray();
    }

    // ======== ASN.1 DER Encoding Helpers ========

    private static byte[] asn1Integer(long value) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Encode the value as variable-length big-endian
        BigInteger bi = BigInteger.valueOf(value);
        byte[] valueBytes = bi.toByteArray();
        out.write(0x02); // INTEGER tag
        out.write(asn1Length(valueBytes.length));
        out.write(valueBytes);
        return out.toByteArray();
    }

    private static byte[] asn1Enum(int value) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BigInteger bi = BigInteger.valueOf(value);
        byte[] valueBytes = bi.toByteArray();
        out.write(0x0A); // ENUMERATED tag
        out.write(asn1Length(valueBytes.length));
        out.write(valueBytes);
        return out.toByteArray();
    }

    private static byte[] asn1Boolean(boolean value) throws Exception {
        return new byte[] { 0x01, 0x01, (byte)(value ? 0xFF : 0x00) };
    }

    private static byte[] asn1OctetString(byte[] data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x04); // OCTET STRING tag
        out.write(asn1Length(data.length));
        out.write(data);
        return out.toByteArray();
    }

    private static byte[] asn1ExplicitTag(int tagNum, byte[] content) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Context-specific, constructed
        if (tagNum < 31) {
            out.write(0xA0 | tagNum);
        } else {
            out.write(0xBF); // context, constructed, long form
            if (tagNum < 128) {
                out.write(tagNum);
            } else {
                // Multi-byte tag encoding (base-128)
                if (tagNum < 16384) {
                    out.write(0x80 | (tagNum >> 7));
                    out.write(tagNum & 0x7F);
                } else {
                    out.write(0x80 | (tagNum >> 14));
                    out.write(0x80 | ((tagNum >> 7) & 0x7F));
                    out.write(tagNum & 0x7F);
                }
            }
        }
        out.write(asn1Length(content.length));
        out.write(content);
        return out.toByteArray();
    }

    private static byte[] asn1Length(int length) {
        if (length < 128) {
            return new byte[] { (byte) length };
        } else if (length < 256) {
            return new byte[] { (byte) 0x81, (byte) length };
        } else {
            return new byte[] {
                (byte) 0x82,
                (byte) (length >> 8),
                (byte) (length & 0xFF)
            };
        }
    }

    /**
     * Build TBS (To-Be-Signed) certificate structure.
     */
    private static byte[] buildTBSCertificate(
            PublicKey subjectKey,
            X509Certificate issuerCert,
            byte[] attestationExtension,
            String algorithm) throws Exception {

        ByteArrayOutputStream tbs = new ByteArrayOutputStream();

        // version [0] EXPLICIT INTEGER (v3 = 2)
        tbs.write(new byte[] {
            (byte) 0xA0, 0x03, 0x02, 0x01, 0x02
        });

        // serialNumber INTEGER (random)
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        byte[] serialBytes = serial.toByteArray();
        tbs.write(0x02);
        tbs.write(asn1Length(serialBytes.length));
        tbs.write(serialBytes);

        // signature AlgorithmIdentifier
        tbs.write(getAlgorithmIdentifier(algorithm));

        // issuer Name (from keybox cert)
        tbs.write(issuerCert.getSubjectX500Principal().getEncoded());

        // validity
        Calendar cal = Calendar.getInstance();
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 30);
        Date notAfter = cal.getTime();
        tbs.write(buildValidity(notBefore, notAfter));

        // subject Name (same as issuer for attestation leaf)
        tbs.write(issuerCert.getSubjectX500Principal().getEncoded());

        // subjectPublicKeyInfo
        tbs.write(subjectKey.getEncoded());

        // extensions [3] EXPLICIT SEQUENCE
        ByteArrayOutputStream extsSeq = new ByteArrayOutputStream();

        // Key attestation extension
        ByteArrayOutputStream extEntry = new ByteArrayOutputStream();
        // OID
        byte[] oidBytes = encodeOid(ATTESTATION_EXTENSION_OID);
        extEntry.write(0x06); // OID tag
        extEntry.write(asn1Length(oidBytes.length));
        extEntry.write(oidBytes);
        // critical = false (omit)
        // value OCTET STRING wrapping the extension content
        extEntry.write(asn1OctetString(attestationExtension));

        byte[] extEntryBytes = extEntry.toByteArray();
        ByteArrayOutputStream extEntrySeq = new ByteArrayOutputStream();
        extEntrySeq.write(0x30); // SEQUENCE
        extEntrySeq.write(asn1Length(extEntryBytes.length));
        extEntrySeq.write(extEntryBytes);

        extsSeq.write(0x30); // extensions SEQUENCE
        byte[] extSeqContent = extEntrySeq.toByteArray();
        extsSeq.write(asn1Length(extSeqContent.length));
        extsSeq.write(extSeqContent);

        // Wrap in [3] EXPLICIT
        byte[] extsSeqBytes = extsSeq.toByteArray();
        tbs.write(0xA3); // [3] EXPLICIT
        tbs.write(asn1Length(extsSeqBytes.length));
        tbs.write(extsSeqBytes);

        // Wrap TBS in SEQUENCE
        byte[] tbsContent = tbs.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x30); // SEQUENCE
        result.write(asn1Length(tbsContent.length));
        result.write(tbsContent);
        return result.toByteArray();
    }

    private static byte[] getAlgorithmIdentifier(String algorithm) {
        if ("EC".equals(algorithm)) {
            // SHA256withECDSA OID: 1.2.840.10045.4.3.2
            return new byte[] {
                0x30, 0x0A,
                0x06, 0x08,
                0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x04, 0x03, 0x02
            };
        } else {
            // SHA256withRSA OID: 1.2.840.113549.1.1.11
            return new byte[] {
                0x30, 0x0D,
                0x06, 0x09,
                0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x0B,
                0x05, 0x00
            };
        }
    }

    private static byte[] buildValidity(Date notBefore, Date notAfter) throws Exception {
        ByteArrayOutputStream val = new ByteArrayOutputStream();
        val.write(asn1GeneralizedTime(notBefore));
        val.write(asn1GeneralizedTime(notAfter));

        byte[] valBytes = val.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x30);
        result.write(asn1Length(valBytes.length));
        result.write(valBytes);
        return result.toByteArray();
    }

    private static byte[] asn1GeneralizedTime(Date date) {
        java.text.SimpleDateFormat sdf =
                new java.text.SimpleDateFormat("yyyyMMddHHmmss'Z'");
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        String time = sdf.format(date);
        byte[] timeBytes = time.getBytes();
        byte[] result = new byte[timeBytes.length + 2];
        result[0] = 0x18; // GeneralizedTime tag
        result[1] = (byte) timeBytes.length;
        System.arraycopy(timeBytes, 0, result, 2, timeBytes.length);
        return result;
    }

    /**
     * Encode a dotted OID string to DER bytes (without tag+length).
     */
    private static byte[] encodeOid(String oid) throws Exception {
        String[] parts = oid.split("\\.");
        int[] components = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            components[i] = Integer.parseInt(parts[i]);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // First two components encoded as 40*c0 + c1
        out.write(40 * components[0] + components[1]);

        for (int i = 2; i < components.length; i++) {
            encodeOidComponent(out, components[i]);
        }
        return out.toByteArray();
    }

    private static void encodeOidComponent(ByteArrayOutputStream out, int value) {
        if (value < 128) {
            out.write(value);
        } else {
            // Base-128 encoding
            int numBytes = 0;
            int temp = value;
            while (temp > 0) {
                numBytes++;
                temp >>= 7;
            }
            for (int i = numBytes - 1; i >= 0; i--) {
                int b = (value >> (7 * i)) & 0x7F;
                if (i > 0) b |= 0x80;
                out.write(b);
            }
        }
    }

    /**
     * Build the complete X.509 Certificate DER structure.
     */
    private static byte[] buildX509Certificate(
            byte[] tbsCertificate,
            byte[] signatureValue,
            String algorithm) throws Exception {

        ByteArrayOutputStream cert = new ByteArrayOutputStream();

        // tbsCertificate (already a SEQUENCE)
        cert.write(tbsCertificate);

        // signatureAlgorithm
        cert.write(getAlgorithmIdentifier(algorithm));

        // signatureValue BIT STRING
        ByteArrayOutputStream sigBits = new ByteArrayOutputStream();
        sigBits.write(0x03); // BIT STRING tag
        sigBits.write(asn1Length(signatureValue.length + 1));
        sigBits.write(0x00); // unused bits
        sigBits.write(signatureValue);
        cert.write(sigBits.toByteArray());

        // Wrap in SEQUENCE
        byte[] certContent = cert.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x30); // SEQUENCE
        result.write(asn1Length(certContent.length));
        result.write(certContent);
        return result.toByteArray();
    }

    /**
     * Key information for the attested key.
     * Used to generate correct AuthorizationList tags matching actual key type.
     */
    private static class KeyInfo {
        final int algorithm;    // KM_ALGORITHM_EC or KM_ALGORITHM_RSA
        final String algorithmName;
        final int keySize;      // bits (256 for EC P-256, 2048/4096 for RSA)
        final int ecCurve;      // KM_EC_CURVE_P256 or -1 for RSA

        KeyInfo(int algorithm, String name, int keySize, int ecCurve) {
            this.algorithm = algorithm;
            this.algorithmName = name;
            this.keySize = keySize;
            this.ecCurve = ecCurve;
        }
    }
}
