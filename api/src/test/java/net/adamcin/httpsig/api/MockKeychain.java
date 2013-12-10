package net.adamcin.httpsig.api;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 *
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

    public Set<String> getKeyIds() {
        return Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(mockIdentity.getId())));
    }

    public Set<Algorithm> getAlgorithms() {
        return mockIdentity != null ? mockIdentity.getAlgorithms() : Collections.<Algorithm>emptySet();
    }

    public Keychain discard() {
        return new DefaultKeychain();
    }

    public Key currentKey() {
        return this.mockIdentity;
    }

    public boolean isEmpty() {
        return this.mockIdentity != null;
    }

    public Keychain filterAlgorithms(Collection<Algorithm> algorithms) {
        throw new UnsupportedOperationException("filterAlgorithms not implemented");
    }

    public Map<String, Key> toMap(KeyIdentifier keyIdentifier) {
        return Collections.<String, Key>singletonMap(keyIdentifier != null ?
                                                             keyIdentifier.getId(this.mockIdentity) : this.mockIdentity.getId(),
                                                     this.mockIdentity);
    }

    public Iterator<Key> iterator() {
        return Collections.<Key>singletonList(mockIdentity).iterator();
    }
}
