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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Representation of the "Authorization: Signature..." header sent by the client in response to a {@link Challenge}
 */
public final class Authorization implements Serializable {

    private static final long serialVersionUID = -5642537789425001043L;

    private final String keyId;
    private final String signature;
    private final List<String> headers;
    private final Algorithm algorithm;

    /**
     * Construct an {@link Authorization} instance
     * @param keyId the key identifier
     * @param signature the Base64-encoded Signature
     * @param headers the list of signed headers
     * @param algorithm the signing algorithm used
     */
    public Authorization(final String keyId, final String signature, final List<String> headers, final Algorithm algorithm) {
        this.keyId = keyId;
        this.signature = signature;
        this.headers = headers != null ? Collections.unmodifiableList(new ArrayList<String>(headers)) : Constants.DEFAULT_HEADERS;
        this.algorithm = algorithm;
    }

    public String getKeyId() {
        return keyId;
    }

    /**
     * @return the signature as a Base64-encoded string
     */
    public String getSignature() {
        return signature;
    }

    /**
     * @return the signature as an unencoded byte array for verification using a {@link Verifier}
     */
    public byte[] getSignatureBytes() {
        return Base64.fromBase64String(this.signature);
    }

    public List<String> getHeaders() {
        return headers;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * @return the constructed {@link Authorization} header value
     */
    public String getHeaderValue() {
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put(Constants.KEY_ID, keyId);
        params.put(Constants.SIGNATURE, signature);
        params.put(Constants.HEADERS, Constants.constructTokensString(getHeaders()));
        params.put(Constants.ALGORITHM, algorithm.getName());
        return Constants.constructRFC2617(params);
    }

    @Override
    public String toString() {
        return getHeaderValue();
    }

    /**
     * Parse an Authorization header value to construct an {@link Authorization} instance
     * @param header the Authorization header value
     * @return the {@link Authorization} instance
     */
    public static Authorization parse(String header) {
        if (header != null && header.toLowerCase().startsWith(Constants.SCHEME.toLowerCase())) {
            Map<String, String> params = Constants.parseRFC2617(header);

            if (params.containsKey(Constants.KEY_ID)
                    && params.containsKey(Constants.SIGNATURE)
                    && params.containsKey(Constants.ALGORITHM)) {

                String keyId = params.get(Constants.KEY_ID);
                String signature = params.get(Constants.SIGNATURE);
                String algorithm = params.get(Constants.ALGORITHM);

                // headers are optional. use default headers if undefined
                String headers = params.get(Constants.HEADERS);

                return new Authorization(keyId, signature, headers != null ? Constants.parseTokens(headers) : Constants.DEFAULT_HEADERS, Algorithm.forName(algorithm));
            }
        }

        return null;
    }
}
