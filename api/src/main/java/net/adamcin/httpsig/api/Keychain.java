package net.adamcin.httpsig.api;

import java.util.Set;

/**
 * Self-reducing set of {@link Key}s
 */
public interface Keychain {

    /**
     * Returns true if this repository contains an {@link Key} with the given fingerprint
     * @param fingerprint
     * @return
     */
    boolean contains(String fingerprint);

    /**
     * @param fingerprint a public key fingerprint
     * @return an {@link Key} where {@code getId().equals(fingerprint)} or null if none exists
     */
    Key get(String fingerprint);

    /**
     * @return a set containing each {@link Key}'s fingerprint
     */
    Set<String> fingerprints();

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
    Key get();

    /**
     *
     * @return
     */
    boolean isEmpty();
}
