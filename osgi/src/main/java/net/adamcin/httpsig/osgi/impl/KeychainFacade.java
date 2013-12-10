package net.adamcin.httpsig.osgi.impl;

import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.KeyIdentifier;
import net.adamcin.httpsig.api.Keychain;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 */
public class KeychainFacade implements Keychain {

    private final Keychain keychain;

    public KeychainFacade(Keychain keychain) {
        this.keychain = keychain;
    }

    public Set<Algorithm> getAlgorithms() {
        return this.keychain.getAlgorithms();
    }

    public Keychain filterAlgorithms(Collection<Algorithm> algorithms) {
        return new KeychainFacade(this.keychain.filterAlgorithms(algorithms));
    }

    public Keychain discard() {
        return new KeychainFacade(this.keychain.discard());
    }

    public Key currentKey() {
        return this.keychain.currentKey();
    }

    public Map<String, Key> toMap(KeyIdentifier keyIdentifier) {
        return this.keychain.toMap(keyIdentifier);
    }

    public boolean isEmpty() {
        return this.keychain.isEmpty();
    }

    public Iterator<Key> iterator() {
        return this.keychain.iterator();
    }
}
