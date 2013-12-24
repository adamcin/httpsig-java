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

package net.adamcin.httpsig.ssh.jce;

import net.adamcin.httpsig.api.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Default {@link net.adamcin.httpsig.api.Key} implementation for OpenSSH-compliant keys (RSA/DSA)
 */
public final class SSHKey implements FingerprintableKey {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKey.class);
    private static final byte[] EMPTY_BYTES = new byte[0];

    private final KeyFormat keyFormat;
    private final KeyPair keyPair;
    private final String fingerprint;

    public SSHKey(KeyFormat keyFormat, KeyPair keyPair) {
        if (keyFormat == null) {
            throw new IllegalArgumentException("keyFormat must not be null");
        } else {
            this.keyFormat = keyFormat;
        }
        if (keyPair == null) {
            throw new IllegalArgumentException("keyFormat must not be null");
        }
        if (keyPair.getPublic() == null) {
            throw new IllegalArgumentException("publicKey must not be null");
        }
        this.keyPair = keyPair;
        this.fingerprint = keyFormat.getFingerprint(keyPair.getPublic());
    }

    public SSHKey(KeyFormat keyFormat, PublicKey publicKey,
                  PrivateKey privateKey) {
        this(keyFormat, new KeyPair(publicKey, privateKey));
    }

    /**
     * {@inheritDoc}
     */
    public String getId() {
        return this.fingerprint;
    }

    /**
     * {@inheritDoc}
     */
    public String getFingerprint() {
        return this.fingerprint;
    }

    /**
     * {@inheritDoc}
     */
    public Set<Algorithm> getAlgorithms() {
        return Collections.unmodifiableSet(new LinkedHashSet<Algorithm>(keyFormat.getSignatureAlgorithms()));
    }

    /**
     * {@inheritDoc}
     */
    public boolean canVerify() {
        return this.keyPair.getPublic() != null;
    }

    /**
     * {@inheritDoc}
     */
    public boolean canSign() {
        return this.keyPair.getPrivate() != null;
    }

    /**
     * {@inheritDoc}
     */
    public boolean verify(Algorithm algorithm, byte[] challengeHash, byte[] signatureBytes) {
        if (challengeHash == null) {
            throw new IllegalArgumentException("challengeHash cannot be null.");
        }

        if (signatureBytes == null) {
            throw new IllegalArgumentException("signatureBytes cannot be null.");
        }

        if (keyPair.getPublic() == null) {
            LOGGER.warn("[verify] this identity cannot be used for verification because it lacks a public key.");
        }

        Signature signature = keyFormat.getSignatureInstance(algorithm);
        if (signature != null) {
            try {
                signature.initVerify(keyPair.getPublic());
                signature.update(challengeHash);
                return signature.verify(signatureBytes);
            } catch (SignatureException e) {
                LOGGER.error("[verify] failed to verify signature.", e);
            } catch (InvalidKeyException e) {
                LOGGER.error("[verify] failed to verify signature due to invalid public key.", e);
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public byte[] sign(Algorithm algorithm, byte[] challengeHash) {
        if (challengeHash == null) {
            throw new IllegalArgumentException("challengeHash cannot be null.");
        }

        if (keyPair.getPrivate() == null) {
            LOGGER.warn("[sign] this identity cannot be used for signing because it lacks a private key.");
            return null;
        }

        Signature signature = keyFormat.getSignatureInstance(algorithm);
        if (signature != null) {
            try {
                signature.initSign(keyPair.getPrivate());
                signature.update(challengeHash);
                return signature.sign();
            } catch (SignatureException e) {
                LOGGER.error("[sign] failed to sign challengeHash.", e);
            } catch (InvalidKeyException e) {
                LOGGER.error("[sign] failed to sign challengeHash due to invalid private key.", e);
            }
        }

        return EMPTY_BYTES;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        SSHKey that = (SSHKey) o;

        if (!fingerprint.equals(that.fingerprint)) {
            return false;
        }
        if (keyFormat != that.keyFormat) {
            return false;
        }
        if (keyPair.getPrivate() != null ? !keyPair.getPrivate().equals(that.keyPair.getPrivate()) : that.keyPair.getPrivate() != null) {
            return false;
        }
        if (keyPair.getPublic() != null ? !keyPair.getPublic().equals(that.keyPair.getPublic()) : that.keyPair.getPublic() != null) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        int result = fingerprint.hashCode();
        result = 31 * result + keyFormat.hashCode();
        result = 31 * result + (keyPair.getPublic() != null ? keyPair.getPublic().hashCode() : 0);
        result = 31 * result + (keyPair.getPrivate() != null ? keyPair.getPrivate().hashCode() : 0);
        return result;
    }
}
