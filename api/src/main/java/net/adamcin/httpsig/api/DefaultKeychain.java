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

    private final List<Key> keys = new ArrayList<Key>();
    private final Set<Algorithm> _algorithms = new LinkedHashSet<Algorithm>();

    public DefaultKeychain() {
        this(null);
    }

    public DefaultKeychain(Collection<? extends Key> identities) {
        if (identities != null) {
            this.addAll(identities);
        }
    }

    public Set<Algorithm> getAlgorithms() {
        return Collections.unmodifiableSet(_algorithms);
    }

    public int size() {
        return keys.size();
    }

    public boolean isEmpty() {
        return keys.isEmpty();
    }

    public boolean contains(Object o) {
        return keys.contains(o);
    }

    public Iterator<Key> iterator() {
        return keys.iterator();
    }

    public Object[] toArray() {
        return keys.toArray();
    }

    public <T> T[] toArray(T[] a) {
        return keys.toArray(a);
    }

    public boolean add(Key key) {
        _algorithms.addAll(key.getAlgorithms());
        return keys.add(key);
    }

    public boolean remove(Object o) {
        return keys.remove(o);
    }

    public boolean containsAll(Collection<?> c) {
        return keys.containsAll(c);
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
        return keys.removeAll(c);
    }

    public boolean retainAll(Collection<?> c) {
        return keys.retainAll(c);
    }

    public void clear() {
        keys.clear();
        _algorithms.clear();
    }

    public Keychain discard() {
        if (isEmpty()) {
            throw new NoSuchElementException("keychain is empty");
        } else if (size() > 1) {
            List<Key> _keys = new ArrayList<Key>(keys.size() - 1);
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

    /**
     *
     * @return
     * @throws NoSuchElementException if the keychain is empty
     */
    public Key currentKey() {
        if (isEmpty()) {
            throw new NoSuchElementException("keychain is empty");
        } else {
            return iterator().next();
        }
    }

    public Keychain filterAlgorithms(Collection<Algorithm> algorithms) {
        ArrayList<Key> filteredKeys = new ArrayList<Key>();
        for (Key key : this) {
            for (Algorithm algorithm : key.getAlgorithms()) {
                if (algorithms.contains(algorithm)) {
                    filteredKeys.add(key);
                }
            }
        }

        return new DefaultKeychain(filteredKeys);
    }

    public Map<String, Key> toMap(KeyIdentifier keyIdentifier) {
        KeyIdentifier identifier = keyIdentifier != null ? keyIdentifier : Constants.DEFAULT_KEY_IDENTIFIER;
        LinkedHashMap<String, Key> map = new LinkedHashMap<String, Key>(this.size());
        for (Key key : this) {
            String keyId = identifier.getId(key);
            if (keyId != null) {
                map.put(keyId, key);
            }
        }
        return Collections.unmodifiableMap(map);
    }
}
