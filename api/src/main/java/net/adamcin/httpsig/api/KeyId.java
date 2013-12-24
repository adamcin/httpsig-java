package net.adamcin.httpsig.api;

/**
 * Interface used by a {@link Keychain} to generate keyId's from the {@link Key}s that it contains
 */
public interface KeyId {

    /**
     * @param key the {@link Key} to identify
     * @return the generated keyId or null if the {@link Key} cannot be identified
     */
    String getId(Key key);
}
