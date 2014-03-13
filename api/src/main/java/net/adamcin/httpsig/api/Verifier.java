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

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

/**
 * The Server-Side component of the protocol which verifies {@link Authorization} headers using SSH Public Keys
 */
public final class Verifier {
    public static final long DEFAULT_SKEW = 300000L;

    private final Keychain keychain;
    private KeyId keyId;
    private long skew = DEFAULT_SKEW;

    public Verifier(Keychain keychain) {
        this(keychain, null);
    }

    public Verifier(Keychain keychain, KeyId keyId) {
        this.keychain = keychain != null ? keychain : new DefaultKeychain();
        this.keyId = new CanVerifyId(keyId != null ? keyId : Constants.DEFAULT_KEY_IDENTIFIER);
    }

    public Keychain getKeychain() {
        return keychain;
    }

    /**
     * @return server skew in milliseconds
     */
    public long getSkew() {
        return skew;
    }

    /**
     * set to a positive number to enforce date header check within server time +/- skew. set to negative number to disable this check altogether.
     * @param skew new server skew in milliseconds
     */
    public void setSkew(long skew) {
        this.skew = skew;
    }

    /**
     * Selects an appropriate {@link Key} from the {@link Keychain} matching the keyId specified in the
     * {@link Authorization}. This method is called by
     * {@link #verifyWithResult(Challenge, RequestContent, Authorization)}, but can be called by client code to
     * retrieve the identified {@link Key} directly
     * @since 1.0.6
     * @param authorization the {@link Authorization} header
     * @return a matching {@link Key} or null
     */
    public Key selectKey(Authorization authorization) {
        return keychain.toMap(this.keyId).get(authorization.getKeyId());
    }

    /**
     * Verifies the provided {@link Authorization} header against the original {@link Challenge}
     * @param challenge the WWW-Authenticate challenge sent to the client in the previous response
     * @param requestContent the {@link RequestContent} containing the request header content
     * @param authorization the {@link Authorization} header to verify
     * @return true if valid ({@link VerifyResult#SUCCESS}), false otherwise
     */
    public boolean verify(Challenge challenge, RequestContent requestContent, Authorization authorization) {
        return verifyWithResult(challenge, requestContent, authorization) == VerifyResult.SUCCESS;
    }

    /**
     * Verifies the provided {@link Authorization} header against the original {@link Challenge}
     * @param challenge the WWW-Authenticate challenge sent to the client in the previous response
     * @param requestContent the {@link RequestContent} containing the request header content
     * @param authorization the {@link Authorization} header to verify
     * @return
     */
    public VerifyResult verifyWithResult(Challenge challenge, RequestContent requestContent, Authorization authorization) {
        if (challenge == null) {
            throw new IllegalArgumentException("challenge cannot be null");
        }

        if (requestContent == null) {
            throw new IllegalArgumentException("requestContent cannot be null");
        }

        if (authorization == null) {
            throw new IllegalArgumentException("authorization cannot be null");
        }

        // verify that all headers required by the challenge are declared by the authorization
        for (String header : challenge.getHeaders()) {
            if (!header.startsWith(":") && !authorization.getHeaders().contains(header)) {
                return VerifyResult.CHALLENGE_NOT_SATISFIED;
            }
        }

        // verify that all headers declared by the authorization are present in the request
        for (String header : authorization.getHeaders()) {
            if (requestContent.getHeaderValues(header).isEmpty()) {
                return VerifyResult.INCOMPLETE_REQUEST;
            }
        }

        // if date is declared by the authorization, verify that its value is within $skew of the current time
        if (authorization.getHeaders().contains(Constants.HEADER_DATE) && skew >= 0) {
            Date requestTime = requestContent.getDateGMT();
            Date currentTime = new GregorianCalendar(TimeZone.getTimeZone("UTC")).getTime();
            Date past = new Date(currentTime.getTime() - skew);
            Date future = new Date(currentTime.getTime() + skew);
            if (requestTime.before(past) || requestTime.after(future)) {
                return VerifyResult.EXPIRED_DATE_HEADER;
            }
        }

        Key key = selectKey(authorization);
        if (key == null) {
            return VerifyResult.KEY_NOT_FOUND;
        }

        if (key.verify(authorization.getAlgorithm(),
                                      requestContent.getContent(authorization.getHeaders(), Constants.CHARSET),
                                      authorization.getSignatureBytes())) {
            return VerifyResult.SUCCESS;
        } else {
            return VerifyResult.FAILED_KEY_VERIFY;
        }
    }

    private static class CanVerifyId implements KeyId {
        private KeyId delegatee;

        private CanVerifyId(KeyId delegatee) {
            this.delegatee = delegatee;
        }

        public String getId(Key key) {
            if (key != null && key.canVerify()) {
                return delegatee.getId(key);
            }
            return null;
        }
    }
}
