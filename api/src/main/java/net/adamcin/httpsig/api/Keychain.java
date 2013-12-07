package net.adamcin.httpsig.api;

import java.util.Set;

/**
 * Self-reducing list of {@link Key}s, searchable by keyId
 */
public interface Keychain {

    /**
     * @param keyId a public key fingerprint
     * @return an {@link Key} where {@code getId().equals(fingerprint)} or null if none exists
     */
    Key findKey(String keyId);

    /**
     * @return a set containing the keyIds of all the {@link Key}s in this {@link Keychain}
     */
    Set<String> keyIds();

    /**
     * @return a {@link Set} containing the union of all algorithms supported by each {@link Key} in this {@link Keychain}
     */
    Set<Algorithm> algorithms();

    /**
     * @return a reference to a {@link Keychain} which excludes the current {@link Key}.
     */
    Keychain discard();

    /**
     * @return a reference to the current {@link Key}.
     */
    Key currentKey();

    /**
     * @return a the current {@link Key}'s keyId.
     */
    String currentKeyId();

    /**
     * @return true if this {@link Keychain} has no more keys
     */
    boolean isEmpty();
}
