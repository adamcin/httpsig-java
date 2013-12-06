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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Instance of a Signer, used by an HTTP client to sign a {@link Challenge} and create an {@link Authorization}
 */
public final class Signer {

    private final Keychain keychain;

    public Signer() {
        this(null);
    }

    public Signer(Keychain keychain) {
        this.keychain = keychain != null ? keychain : new DefaultKeychain();
    }

    public Keychain getKeychain() {
        return keychain;
    }

    /**
     * @return a set of public key fingerprints to offer in client HTTP request
     */
    public Set<String> getFingerprints() {
        Set<String> fingerprints = new HashSet<String>();
        Set<String> _fingerprints = this.keychain.fingerprints();
        if (_fingerprints != null) {
            for (String fingerprint : _fingerprints) {
                if (Constants.validateFingerprint(fingerprint)) {
                    fingerprints.add(fingerprint);
                }
            }
        }
        return Collections.unmodifiableSet(fingerprints);
    }

    /**
     * Signs a {@link Challenge} and returns an {@link Authorization} header
     * @param challenge the challenge header to be signed
     * @return a signed SSHKey {@link Authorization} header or null if no identities could sign the {@link Challenge}
     */
    public Authorization sign(Challenge challenge) {
        if (challenge != null) {

            Key key = this.keychain.get(challenge.getFingerprint());

            if (key != null) {

                Algorithm algo = null;
                for (Algorithm algorithm : challenge.getAlgorithms()) {
                    if (key.getAlgorithms().contains(algorithm)) {
                        algo = algorithm;
                        break;
                    }
                }

                byte[] signature = key.sign(algo, challenge.getHashBytes());

                if (signature != null) {
                    return new Authorization(challenge.getNonce(), signature, algo);
                }
            }
        }

        return null;
    }
}
