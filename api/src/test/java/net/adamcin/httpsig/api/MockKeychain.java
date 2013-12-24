/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

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

    public Map<String, Key> toMap(KeyId keyId) {
        return Collections.<String, Key>singletonMap(keyId != null ?
                                                             keyId.getId(this.mockIdentity) : this.mockIdentity.getId(),
                                                     this.mockIdentity);
    }

    public Iterator<Key> iterator() {
        return Collections.<Key>singletonList(mockIdentity).iterator();
    }
}
