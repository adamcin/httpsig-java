package net.adamcin.httpsig.jce;

import net.adamcin.httpsig.api.Key;

/**
 * Interface for public keys which can provide a uniquely identifying fingerprint
 */
public interface FingerprintableKey extends Key {

    /**
     * @return the public key fingerprint
     */
    String getFingerprint();
}
