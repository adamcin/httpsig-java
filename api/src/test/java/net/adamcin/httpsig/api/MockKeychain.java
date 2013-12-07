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

    public Key findKey(String fingerprint) {
        if (fingerprint != null && fingerprint.equals(mockIdentity.getId())) {
            return mockIdentity;
        }
        return null;
    }

    public Set<String> keyIds() {
        return Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(mockIdentity.getId())));
    }

    public Set<Algorithm> algorithms() {
        return mockIdentity != null ? mockIdentity.getAlgorithms() : Collections.<Algorithm>emptySet();
    }

    public Keychain discard() {
        return new DefaultKeychain();
    }

    public Key currentKey() {
        return this.mockIdentity;
    }

    public String currentKeyId() {
        return this.mockIdentity.getId();
    }

    public boolean isEmpty() {
        return this.mockIdentity != null;
    }
}
