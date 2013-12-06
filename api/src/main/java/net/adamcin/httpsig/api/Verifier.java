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

import java.util.Collection;

/**
 * The Server-Side component of the protocol which verifies {@link Authorization} headers using SSH Public Keys
 */
public final class Verifier {

    private Keychain keychain;

    public Verifier() {
        this(null);
    }

    public Verifier(Keychain keychain) {
        this.keychain = keychain != null ? keychain : new DefaultKeychain();
    }

    public Keychain getKeychain() {
        return keychain;
    }

    /**
     * Selects a public key fingerprint from those offered by the client based on what is available from the
     * {@link Keychain}
     * @param fingerprints a collection of fingerprints offered in the client request
     * @return a single preferred public key fingerprint, or null if none match
     */
    public String select(Collection<String> fingerprints) {
        if (fingerprints != null) {
            for (String fingerprint : fingerprints) {
                if (Constants.validateFingerprint(fingerprint) && keychain.contains(fingerprint)) {
                    return fingerprint;
                }
            }
        }
        return null;
    }

    /**
     * Verifies the provided {@link Authorization} header against the original {@link Challenge}
     * @param challenge the WWW-Authenticate challenge sent to the client in the previous response
     * @param authorization the authorization header
     * @return true if valid, false if not
     */
    public boolean verify(Challenge challenge, Authorization authorization) {
        if (challenge == null || authorization == null) {
            return false;
        }

        Key key = keychain.get(challenge.getFingerprint());
        if (key.getAlgorithms().contains(authorization.getAlgorithm())) {
            return key != null && key.verify(authorization.getAlgorithm(), challenge.getHashBytes(), authorization.getSignatureBytes());
        } else {
            return false;
        }
    }
}
