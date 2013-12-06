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
 * Representation of the "Authorization: SSHKey ..." header sent by the client in response to a {@link Challenge}
 */
public final class Authorization implements Serializable {

    @Deprecated
    private final String token;

    private final String keyId;
    private final String signature;
    private final List<String> headers;
    private final Algorithm algorithm;

    public Authorization(final String token, final String keyId, final String signature, final List<String> headers, final Algorithm algorithm) {
        this.token = token;
        this.keyId = keyId;
        this.signature = signature;
        this.headers = headers != null ? Collections.unmodifiableList(new ArrayList<String>(headers)) : Collections.<String>emptyList();
        this.algorithm = algorithm;
    }

    public Authorization(String token, final String keyId, byte[] signatureBytes, final List<String> headers, final Algorithm algorithm) {
        this.token = token;
        this.keyId = keyId;
        this.signature = Base64.toBase64String(signatureBytes);
        this.headers = headers != null ? Collections.unmodifiableList(new ArrayList<String>(headers)) : Collections.<String>emptyList();
        this.algorithm = algorithm;
    }

    public String getToken() {
        return token;
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

    public String getHeaderValue() {
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put(Constants.TOKEN, token);
        params.put(Constants.FINGERPRINT, keyId);
        params.put(Constants.SIGNATURE, signature);
        params.put(Constants.ALGORITHM, algorithm.getName());
        return Constants.constructRFC2617(params);
    }

    @Override
    public String toString() {
        return getHeaderValue();
    }

    public static Authorization parse(String header) {
        if (header == null) {
            return null;
        }

        Map<String, String> params = Constants.parseRFC2617(header);

        if (params.containsKey(Constants.FINGERPRINT) && params.containsKey(Constants.HEADERS) && params.containsKey(Constants.SIGNATURE)
                && params.containsKey(Constants.ALGORITHM)) {

            String token = params.get(Constants.TOKEN);
            String keyId = params.get(Constants.FINGERPRINT);
            String signature = params.get(Constants.SIGNATURE);
            String headers = params.get(Constants.HEADERS);
            String algorithm = params.get(Constants.ALGORITHM);

            return new Authorization(token, keyId, signature, Constants.parseTokens(headers), Algorithm.forName(algorithm));
        } else {
            return null;
        }
    }
}
