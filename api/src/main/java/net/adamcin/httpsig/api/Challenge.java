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

    private static final long serialVersionUID = 4044394118184261470L;

    private final String realm;
    private final List<String> headers;
    private final List<Algorithm> algorithms;

    /**
     * Construct a {@link Challenge} instance
     * @param realm the authentication realm
     * @param headers the list of required headers
     * @param algorithms the list of supported algorithms
     */
    public Challenge(final String realm,
                     final List<String> headers,
                     final Collection<Algorithm> algorithms) {
        this.realm = realm;
        this.headers = headers != null ? Constants.filterHeaders(new ArrayList<String>(headers)) : Constants.DEFAULT_HEADERS;
        this.algorithms = algorithms != null ? Arrays.asList(algorithms.toArray(new Algorithm[algorithms.size()])) : Collections.<Algorithm>emptyList();
    }

    public String getRealm() {
        return realm;
    }

    public List<String> getHeaders() {
        return headers;
    }

    public List<Algorithm> getAlgorithms() {
        return algorithms;
    }

    /**
     * @return the constructed value of the WWW-Authenticate header
     */
    public String getHeaderValue() {
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put(Constants.REALM, this.realm);
        params.put(Constants.HEADERS, Constants.constructTokensString(getHeaders()));
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
        List<String> tokens = Constants.parseTokens(algorithms);
        List<Algorithm> algorithmList = new ArrayList<Algorithm>();
        for (String token : tokens) {
            Algorithm algorithm = Algorithm.forName(token);
            if (algorithm != null) {
                algorithmList.add(algorithm);
            }
        }
        return Collections.unmodifiableList(algorithmList);
    }

    /**
     * Parse a WWW-Authenticate header value to create a {@link Challenge}
     * @param header WWW-Authenticate header value
     * @return a {@link Challenge} header
     */
    public static Challenge parse(final String header) {
        if (header != null && header.toLowerCase().startsWith(Constants.SCHEME.toLowerCase())) {
            Map<String, String> params = Constants.parseRFC2617(header);

            if (params.containsKey(Constants.REALM)
                    && params.containsKey(Constants.ALGORITHMS)) {

                String realm = params.get(Constants.REALM);
                String algorithms = params.get(Constants.ALGORITHMS);

                String headers = params.get(Constants.HEADERS);

                return new Challenge(realm, headers != null ? Constants.parseTokens(headers) : Constants.DEFAULT_HEADERS, parseAlgorithms(algorithms));
            }
        }

        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Challenge challenge = (Challenge) o;

        if (!algorithms.equals(challenge.algorithms)) {
            return false;
        }
        if (!headers.equals(challenge.headers)) {
            return false;
        }
        if (!realm.equals(challenge.realm)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = realm.hashCode();
        result = 31 * result + headers.hashCode();
        result = 31 * result + algorithms.hashCode();
        return result;
    }
}
