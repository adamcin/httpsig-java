/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

package net.adamcin.httpsig.sshjce;

import net.adamcin.httpsig.api.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 *
 */
public enum KeyFormat {

    SSH_DSS(
            "ssh-dss", "DSA", FingerprintGenerator.DSA, Algorithm.SSH_DSS,
            Arrays.asList(Algorithm.SSH_DSS, Algorithm.DSA_SHA1)
    ),
    SSH_RSA(
            "ssh-rsa", "RSA", FingerprintGenerator.RSA, Algorithm.SSH_RSA,
                    Arrays.asList(Algorithm.SSH_RSA, Algorithm.RSA_SHA1, Algorithm.RSA_SHA256, Algorithm.RSA_SHA512)
    ),
    UNKOWN("_unknown_", "_unknown_", FingerprintGenerator.NOP, null, Collections.<Algorithm>emptyList());

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyFormat.class);

    private final String identifier;
    private final String keyAlgorithm;
    private final Algorithm defaultSignature;
    private final List<Algorithm> signatureAlgorithms;
    private final FingerprintGenerator fingerprintGenerator;

    private KeyFormat(String identifier, String keyAlgorithm, FingerprintGenerator fingerprintGenerator,
                      Algorithm defaultSignature, List<Algorithm> signatureAlgorithms) {
        this.identifier = identifier;
        this.keyAlgorithm = keyAlgorithm;
        this.fingerprintGenerator = fingerprintGenerator;
        this.defaultSignature = defaultSignature;
        this.signatureAlgorithms = signatureAlgorithms;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            // should not happen in standard JVM
            e.printStackTrace(System.err);
        }

        return null;
    }

    public List<Algorithm> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    public String getFingerprint(PublicKey publicKey) {
        return fingerprintGenerator.getFingerprint(publicKey);
    }

    public Signature getSignatureInstance(Algorithm algorithm) {
        return getSignatureInstanceInternal(algorithm != null ? algorithm : defaultSignature);
    }

    private static Signature getSignatureInstanceInternal(Algorithm algorithm) {
        if (algorithm != null) {
            try {
                switch (algorithm) {
                    case SSH_DSS:
                        return new SSHDSSSignature();
                    case SSH_RSA:
                        return new SSHRSASignature();
                    case RSA_SHA1:
                        return Signature.getInstance("SHA1withRSA");
                    case RSA_SHA256:
                        return Signature.getInstance("SHA256withRSA");
                    case RSA_SHA512:
                        return Signature.getInstance("SHA512withRSA");
                    case DSA_SHA1:
                        return Signature.getInstance("SHA1withDSA");
                    default:
                        return null;
                }
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("[getSignatureInstance] failed to get signature instance.", e);
            }
        }

        return null;
    }

    public static KeyFormat forIdentifier(String identifier) {
        for (KeyFormat format : KeyFormat.values()) {
            if (format.getIdentifier().equals(identifier)) {
                return format;
            }
        }

        return UNKOWN;
    }

}
