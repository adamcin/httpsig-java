package net.adamcin.httpsig.osgi.impl;

import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.KeyIdentifier;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.httpsig.osgi.OsgiConstants;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

@Component
@Service
@Property(name = OsgiConstants.TARGET_PROPERTY, value = "openssh", propertyPrivate = true)
public class OpenSSHKeychain implements Keychain {
    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSHKeychain.class);

    private Keychain internalKeychain;

    private boolean active = false;

    @Activate
    protected void activate(Map<String, Object> props) {
        DefaultKeychain keychain = new DefaultKeychain();
        try {
            Keychain authorizedKeys = AuthorizedKeys.defaultKeychain();

            for (Key key : authorizedKeys) {
                keychain.add(key);
            }
        } catch (IOException e) {
            LOGGER.error("[activate] failed to load authorized keys file.", e);
        }

        this.internalKeychain = new KeychainFacade(keychain);
        this.active = true;
    }

    @Deactivate
    protected void deactivate() {
        this.active = false;
    }

    public Set<Algorithm> getAlgorithms() {
        if (this.isEmpty()) {
            return Collections.emptySet();
        } else {
            return this.internalKeychain.getAlgorithms();
        }
    }

    public Keychain filterAlgorithms(Collection<Algorithm> algorithms) {
        if (this.isEmpty()) {
            return new KeychainFacade(new DefaultKeychain());
        } else {
            return this.internalKeychain.filterAlgorithms(algorithms);
        }
    }

    public Keychain discard() {
        if (this.isEmpty()) {
            throw new NoSuchElementException("keychain is empty");
        } else {
            return this.internalKeychain.discard();
        }
    }

    public Key currentKey() {
        if (isEmpty()) {
            throw new NoSuchElementException("keychain is empty");
        } else {
            return this.internalKeychain.currentKey();
        }
    }

    public Map<String, Key> toMap(KeyIdentifier keyIdentifier) {
        if (isEmpty()) {
            return Collections.emptyMap();
        } else {
            return internalKeychain.toMap(keyIdentifier);
        }
    }

    public boolean isEmpty() {
        return !this.active || this.internalKeychain.isEmpty();
    }

    public Iterator<Key> iterator() {
        if (isEmpty()) {
            return Collections.emptyIterator();
        } else {
            return internalKeychain.iterator();
        }
    }
}
