package net.adamcin.httpsig.api;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 11/18/13
 * Time: 5:47 PM
 * To change this template use File | Settings | File Templates.
 */
public class MockKeychain implements Keychain {

    private MockKey mockIdentity;

    public MockKeychain(String fingerprint) {
        this.mockIdentity = new MockKey(fingerprint);
    }

    public boolean contains(String fingerprint) {
        return mockIdentity.fingerprint.equals(fingerprint);
    }

    public Key get(String fingerprint) {
        if (contains(fingerprint)) {
            return mockIdentity;
        }
        return null;
    }

    public Set<String> fingerprints() {
        return Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(mockIdentity.getId())));
    }

    public Set<Algorithm> algorithms() {
        return mockIdentity != null ? mockIdentity.getAlgorithms() : Collections.<Algorithm>emptySet();
    }

    public Keychain discard() {
        return new DefaultKeychain();
    }

    public Key get() {
        return this.mockIdentity;
    }

    public boolean isEmpty() {
        return this.mockIdentity != null;
    }
}
