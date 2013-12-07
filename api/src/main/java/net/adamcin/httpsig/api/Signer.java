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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Instance of a Signer, used by an HTTP client to sign a {@link Challenge} and create an {@link Authorization}
 */
public final class Signer {

    private Keychain keychain;

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
     * Signs a {@link Challenge} and returns an {@link Authorization} header
     * @param challenge the challenge header setting the signing rules
     * @param request the Request containing the headers to be signed
     * @return a signed SSHKey {@link Authorization} header or null if no identities could sign the {@link Challenge}
     */
    public Authorization sign(Challenge challenge, Request request) {
        if (challenge != null) {

            if (challenge.getDiscard() != null && !keychain.isEmpty()) {
                if (challenge.getDiscard().equals(keychain.currentKeyId())) {
                    this.keychain = keychain.discard();
                }
            }

            if (!keychain.isEmpty()) {
                Key key = this.keychain.currentKey();

                if (key != null) {

                    Algorithm algo = null;
                    for (Algorithm algorithm : challenge.getAlgorithms()) {
                        if (key.getAlgorithms().contains(algorithm)) {
                            algo = algorithm;
                            break;
                        }
                    }

                    Set<String> signHeaders = new LinkedHashSet<String>();
                    signHeaders.addAll(challenge.getHeaders());

                    if (signHeaders.contains(Constants.HEADER_ALL)) {
                        signHeaders.remove(Constants.HEADER_ALL);
                        signHeaders.addAll(request.getHeaderNames());
                    }

                    List<String> headers = new ArrayList<String>(signHeaders);

                    byte[] signature = key.sign(algo, request.getSignableContent(headers, Constants.CHARSET));

                    if (signature != null) {
                        return new Authorization(this.keychain.currentKeyId(), signature, headers, algo);
                    }
                }

            }
        }

        return null;
    }
}
