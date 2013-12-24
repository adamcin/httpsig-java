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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Instance of a Signer, used by an HTTP client to sign a {@link SignatureContent} and create an {@link Authorization}
 */
public final class Signer {

    private KeyIdentifier keyIdentifier;
    private Keychain keychain;
    private Keychain candidateKeys;
    private Challenge challenge = Constants.PREEMPTIVE_CHALLENGE;

    public Signer() {
        this(null, null);
    }

    public Signer(Keychain keychain) {
        this(keychain, null);
    }

    public Signer(Keychain keychain, KeyIdentifier keyIdentifier) {
        this.keychain = keychain != null ? keychain : new DefaultKeychain();
        this.keyIdentifier = keyIdentifier != null ? keyIdentifier : Constants.DEFAULT_KEY_IDENTIFIER;
        this.candidateKeys = this.keychain.filterAlgorithms(challenge.getAlgorithms());
        this.rotateUntilCanSign();
    }

    private synchronized void rotateUntilCanSign() {
        while (!this.candidateKeys.isEmpty() && !this.candidateKeys.currentKey().canSign()) {
            this.candidateKeys = this.candidateKeys.discard();
        }
    }

    /**
     * @return the original keychain supplied to the {@link Signer}
     */
    public Keychain getKeychain() {
        return keychain;
    }

    /**
     * @see #rotateKeys()
     * @return the {@link Challenge}-filtered and rotated {@link Keychain}
     */
    public Keychain getCandidateKeys() {
        return candidateKeys;
    }

    public KeyIdentifier getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * Call this method to rotate the candidate keys back to the original state.
     * @return true if there is at least one key left after rotation, false otherwise
     */
    public synchronized boolean rotateKeys() {
        return rotateKeys(Constants.PREEMPTIVE_CHALLENGE);
    }

    /**
     * Call this method to rotate the candidate keys according to the provided {@link Challenge}.
     * @param nextChallenge the {@link Challenge} header which was returned for the previous failed request.
     * @return true if there is at least one key left after rotation, false otherwise
     */
    public synchronized boolean rotateKeys(Challenge nextChallenge) {
        return rotateKeys(nextChallenge, null);
    }

    /**
     * Call this method to rotate the candidate keys
     * @param nextChallenge the {@link Challenge} header which was returned for the previous failed request.
     * @param failedAuthz the {@link Authorization} header which failed on the previous request.
     * @return true if there is at least one key left after rotation, false otherwise
     */
    public synchronized boolean rotateKeys(Challenge nextChallenge, Authorization failedAuthz) {
        if (nextChallenge == null) {
            throw new IllegalArgumentException("nextChallenge cannot be null");
        }
        if (this.challenge.equals(nextChallenge)) {
            if (!this.candidateKeys.isEmpty()
                    && failedAuthz != null
                    && this.keyIdentifier.getId(this.candidateKeys.currentKey()).equals(failedAuthz.getKeyId())) {
                this.candidateKeys = this.candidateKeys.discard();
            }
        } else {
            this.candidateKeys = this.keychain.filterAlgorithms(nextChallenge.getAlgorithms());
        }
        this.rotateUntilCanSign();
        this.challenge = nextChallenge;
        return !this.candidateKeys.isEmpty();
    }

    /**
     * Signs a {@link SignatureContent} and returns an {@link Authorization} header
     *
     * @param signatureContent the Request containing the headers to be signed
     * @return a signed {@link Authorization} header or null if no identities could sign the {@link Challenge}
     */
    public Authorization sign(SignatureContent signatureContent) {
        if (!candidateKeys.isEmpty()) {
            Key key = this.candidateKeys.currentKey();

            Algorithm algo = null;
            for (Algorithm algorithm : key.getAlgorithms()) {
                if (challenge.getAlgorithms().contains(algorithm)) {
                    algo = algorithm;
                    break;
                }
            }

            Set<String> signHeaders = new LinkedHashSet<String>();
            signHeaders.addAll(challenge.getHeaders());

            List<String> headers = new ArrayList<String>(signHeaders);

            byte[] signature = key.sign(algo, signatureContent.getContent(headers, Constants.CHARSET));

            if (signature != null) {
                return new Authorization(
                        this.keyIdentifier.getId(key), Base64.toBase64String(signature), headers, algo,
                        this.challenge
                );
            }
        }

        return null;
    }
}
