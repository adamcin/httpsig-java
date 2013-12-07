package net.adamcin.httpsig.api;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * Simple implementation of {@link net.adamcin.httpsig.api.Keychain} backed by a HashMap and
 * modified via {@link Collection} methods
 */
public class DefaultKeychain implements Keychain, Collection<Key> {

    private final List<Key> keys = new ArrayList<Key>();
    private final Set<Algorithm> _algorithms = new LinkedHashSet<Algorithm>();
    private KeyIdentifier keyIdentifier;

    public DefaultKeychain() {
        this(null, null);
    }

    public DefaultKeychain(KeyIdentifier keyIdentifier) {
        this.setKeyIdentifier(keyIdentifier);
    }

    public DefaultKeychain(KeyIdentifier keyIdentifier, Collection<? extends Key> identities) {
        this(keyIdentifier);
        if (identities != null) {
            this.addAll(identities);
        }
    }

    public DefaultKeychain(Collection<? extends Key> identities) {
        this(null, identities);
    }


    public KeyIdentifier getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(KeyIdentifier keyIdentifier) {
        if (keyIdentifier != null) {
            this.keyIdentifier = keyIdentifier;
        } else {
            this.keyIdentifier = Constants.DEFAULT_KEY_IDENTIFIER;
        }
    }


    public Set<String> keyIds() {
        Set<String> idSet = new HashSet<String>();
        for (Key key : keys) {
            idSet.add(this.keyIdentifier.getId(key));
        }
        return Collections.unmodifiableSet(idSet);
    }

    public Set<Algorithm> algorithms() {
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

    public Key findKey(String keyId) {
        if (keyId != null) {
            for (Key key : this) {
                if (keyId.equals(keyIdentifier.getId(key))) {
                    return key;
                }
            }
        }
        return null;
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

    /**
     *
     * @return
     * @throws NoSuchElementException if the keychain is empty
     */
    public String currentKeyId() {
        return keyIdentifier.getId(currentKey());
    }
}
