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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Representation of the "WWW-Authenticate: Signature ..." authentication challenge header sent by the server.
 */
public final class Challenge implements Serializable {
    private static final String CRLF = "\r\n";

    private final String realm;
    private final String fingerprint;
    private final String nonce;
    private final String host;
    private final String userAgent;
    private final List<Algorithm> algorithms;

    public Challenge(final String realm,
                     final String fingerprint,
                     final String nonce,
                     final String host,
                     final String userAgent,
                     final Collection<Algorithm> algorithms) {
        this.realm = realm;
        this.fingerprint = fingerprint;
        this.nonce = nonce;
        this.host = host != null ? host : "";
        this.userAgent = userAgent != null ? userAgent : "";
        this.algorithms = algorithms != null ? Arrays.asList(algorithms.toArray(new Algorithm[algorithms.size()])) : Collections.<Algorithm>emptyList();
    }

    public String getRealm() {
        return realm;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getNonce() {
        return nonce;
    }

    public String getHost() {
        return host;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public List<Algorithm> getAlgorithms() {
        return algorithms;
    }

    public String getHash() {
        return new StringBuilder(host).append(CRLF)
                .append(realm).append(CRLF)
                .append(nonce).append(CRLF)
                .append(userAgent).toString();
    }

    public byte[] getHashBytes() {
        return getHash().getBytes(Constants.CHARSET);
    }

    public String getHeaderValue() {
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put(Constants.REALM, this.realm);
        params.put(Constants.FINGERPRINT, this.fingerprint);
        params.put(Constants.NONCE, this.nonce);
        params.put(Constants.ALGORITHMS, this.getAlgorithmsString());
        return Constants.constructRFC2617(params);
    }

    public String getAlgorithmsString() {
        if (algorithms == null || algorithms.isEmpty()) {
            return "";
        } else {
            StringBuilder _algos = new StringBuilder();
            for (Algorithm algo : algorithms) {
                _algos.append(algo.getName()).append(" ");
            }
            return _algos.toString();
        }
    }

    @Override
    public String toString() {
        return getHeaderValue();
    }

    public static List<Algorithm> parseAlgorithms(String algorithms) {
        if (algorithms == null || algorithms.trim().isEmpty()) {
            return Collections.emptyList();
        } else {
            List<Algorithm> algorithmList = new ArrayList<Algorithm>();
            String[] _algorithms = algorithms.trim().split("\\s+");
            for (String _algo : _algorithms) {
                Algorithm algorithm = Algorithm.forName(_algo);
                if (algorithm != null) {
                    algorithmList.add(algorithm);
                }
            }
            return Collections.unmodifiableList(algorithmList);
        }
    }

    public static Challenge parseChallenge(final String challenge, final String host, final String userAgent) {
        Map<String, String> params = Constants.parseRFC2617(challenge);

        if (params.containsKey(Constants.REALM) && params.containsKey(Constants.FINGERPRINT)
                && params.containsKey(Constants.NONCE) && params.containsKey(Constants.ALGORITHMS)) {
            String realm = params.get(Constants.REALM);
            String fingerprint = params.get(Constants.FINGERPRINT);
            String nonce = params.get(Constants.NONCE);
            String algorithms = params.get(Constants.ALGORITHMS);
            return new Challenge(realm, fingerprint, nonce, host, userAgent, parseAlgorithms(algorithms));
        }

        return null;
    }
}
