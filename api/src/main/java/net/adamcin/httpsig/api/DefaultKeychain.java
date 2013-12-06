package net.adamcin.httpsig.api;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * Simple implementation of {@link net.adamcin.httpsig.api.Keychain} backed by a HashMap and
 * modified via {@link Collection} methods
 */
public class DefaultKeychain implements Keychain, Collection<Key> {

    private final Map<String, Key> _identities = new LinkedHashMap<String, Key>();
    private final Set<Algorithm> _algorithms = new LinkedHashSet<Algorithm>();

    public DefaultKeychain() {
    }

    public DefaultKeychain(Collection<? extends Key> identities) {
        this.addAll(identities);
    }

    public Set<String> fingerprints() {
        return Collections.unmodifiableSet(_identities.keySet());
    }

    public Set<Algorithm> algorithms() {
        return Collections.unmodifiableSet(_algorithms);
    }

    public int size() {
        return _identities.size();
    }

    public boolean isEmpty() {
        return _identities.isEmpty();
    }

    public boolean contains(Object o) {
        return _identities.values().contains(o);
    }

    public Iterator<Key> iterator() {
        return _identities.values().iterator();
    }

    public Object[] toArray() {
        return _identities.values().toArray();
    }

    public <T> T[] toArray(T[] a) {
        return _identities.values().toArray(a);
    }

    public boolean add(Key key) {
        if (key == null || _identities.containsKey(key.getId())) {
            return false;
        } else {
            _algorithms.addAll(key.getAlgorithms());
            return _identities.put(key.getId(), key) != null;
        }
    }

    public boolean remove(Object o) {
        return _identities.values().remove(o);
    }

    public boolean containsAll(Collection<?> c) {
        return _identities.values().containsAll(c);
    }

    public boolean addAll(Collection<? extends Key> c) {
        boolean changed = false;

        if (c != null) {
            for (Key i : c) {
                if (add(i)) {
                    changed = true;
                }
            }
        }

        return changed;
    }

    public boolean removeAll(Collection<?> c) {
        return _identities.values().removeAll(c);
    }

    public boolean retainAll(Collection<?> c) {
        return _identities.values().retainAll(c);
    }

    public void clear() {
        _identities.clear();
        _algorithms.clear();
    }

    public boolean contains(String fingerprint) {
        return _identities.containsKey(fingerprint);
    }

    public Key get(String fingerprint) {
        return _identities.get(fingerprint);
    }

    public Keychain discard() {
        if (isEmpty()) {
            throw new NoSuchElementException("keychain is empty");
        } else if (size() > 1) {
            List<Key> _keys = new ArrayList<Key>(_identities.size() - 1);
            Iterator<Key> _idents = iterator();
            _idents.next();
            while (_idents.hasNext()) {
                _keys.add(_idents.next());
            }

            return new DefaultKeychain(_keys);
        } else {
            return new DefaultKeychain();
        }
    }

    public Key get() {
        if (isEmpty()) {
            throw new NoSuchElementException("keychain is empty");
        } else {
            return iterator().next();
        }
    }
}
