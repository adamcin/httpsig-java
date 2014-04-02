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

/**
 * Limited interface allowing for server-side use of guards and remote service calls
 * @since 1.0.8
 */
public interface Verifier {

    /**
     * @return server skew in milliseconds
     */
    long getSkew();

    /**
     * Selects an appropriate {@link Key} from the {@link Keychain} matching the keyId specified in the
     * {@link Authorization}. This method is called by
     * {@link #verifyWithResult(Challenge, RequestContent, Authorization)}, but can be called by client code to
     * retrieve the identified {@link Key} directly
     * @since 1.0.6
     * @param authorization the {@link Authorization} header
     * @return a matching {@link Key} or null
     */
    Key selectKey(Authorization authorization);

    /**
     * Verifies the provided {@link Authorization} header against the original {@link Challenge}
     * @param challenge the WWW-Authenticate challenge sent to the client in the previous response
     * @param requestContent the {@link RequestContent} containing the request header content
     * @param authorization the {@link Authorization} header to verify
     * @return true if valid ({@link VerifyResult#SUCCESS}), false otherwise
     */
    boolean verify(Challenge challenge, RequestContent requestContent, Authorization authorization);

    /**
     * Verifies the provided {@link Authorization} header against the original {@link Challenge}
     * @param challenge the WWW-Authenticate challenge sent to the client in the previous response
     * @param requestContent the {@link RequestContent} containing the request header content
     * @param authorization the {@link Authorization} header to verify
     * @return a {@link net.adamcin.httpsig.api.VerifyResult}
     */
    VerifyResult verifyWithResult(Challenge challenge, RequestContent requestContent, Authorization authorization);
}
