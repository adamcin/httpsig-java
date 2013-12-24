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

package net.adamcin.httpsig.http.apache3;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Signer;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.auth.AuthenticationException;
import org.apache.commons.httpclient.auth.MalformedChallengeException;
import org.apache.commons.httpclient.auth.RFC2617Scheme;

public final class Http3SignatureAuthScheme extends RFC2617Scheme {

    private boolean rotate = false;
    private Authorization lastAuthz = null;

    public String getSchemeName() {
        return Constants.SCHEME;
    }

    public boolean isConnectionBased() {
        return false;
    }

    public boolean isComplete() {
        return true;
    }

    @Override
    public void processChallenge(String challenge) throws MalformedChallengeException {
        super.processChallenge(challenge);
        this.rotate = true;
    }

    public String authenticate(Credentials credentials, String method, String uri) throws AuthenticationException {
        throw new AuthenticationException("Signature authentication requires access to all request headers");
    }

    public String authenticate(Credentials credentials, HttpMethod method) throws AuthenticationException {
        if (credentials instanceof SignerCredentials) {
            SignerCredentials creds = (SignerCredentials) credentials;
            String headers = this.getParameter(Constants.HEADERS);
            String algorithms = this.getParameter(Constants.ALGORITHMS);

            Challenge challenge = new Challenge(this.getRealm(), Constants.parseTokens(headers), Challenge.parseAlgorithms(algorithms));

            Signer signer = creds.getSigner();
            if (signer != null) {

                if (this.rotate) {
                    this.rotate = false;
                    if (!signer.rotateKeys(challenge, this.lastAuthz)) {
                        signer.rotateKeys(challenge);
                        return null;
                    }
                }

                SignatureBuilder sigBuilder = new SignatureBuilder();
                sigBuilder.setRequestLine(
                        String.format("%s %s HTTP/1.1", method.getName(),
                                      method.getPath() + (method.getQueryString() != null ? "?" + method.getQueryString() : "")));

                for (Header header : method.getRequestHeaders()) {
                    sigBuilder.addHeader(header.getName(), header.getValue());
                }

                if (sigBuilder.getDate() == null) {
                    sigBuilder.addDateNow();
                    method.addRequestHeader(Constants.HEADER_DATE, sigBuilder.getDate());
                }

                Authorization authorization = creds.getSigner().sign(sigBuilder);
                this.lastAuthz = authorization;
                if (authorization != null) {
                    return authorization.getHeaderValue();
                }
            }
        }

        return null;
    }
}
