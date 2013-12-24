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

package net.adamcin.httpsig.http.apache4;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Signer;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.impl.auth.RFC2617Scheme;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.CharArrayBuffer;

public final class Http4SignatureAuthScheme extends RFC2617Scheme {

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
    protected void parseChallenge(CharArrayBuffer buffer, int pos, int len) throws MalformedChallengeException {
        super.parseChallenge(buffer, pos, len);
        this.rotate = true;
    }

    public Header authenticate(Credentials credentials, HttpRequest request)
            throws AuthenticationException {

        if (credentials instanceof SignerCredentials) {
            Signer signer = ((SignerCredentials) credentials).getSigner();
            String headers = this.getParameter(Constants.HEADERS);
            String algorithms = this.getParameter(Constants.ALGORITHMS);

            Challenge challenge = new Challenge(this.getRealm(), Constants.parseTokens(headers), Challenge.parseAlgorithms(algorithms));

            if (this.rotate) {
                this.rotate = false;
                if (!signer.rotateKeys(challenge, this.lastAuthz)) {
                    signer.rotateKeys(challenge);
                    return null;
                }
            }

            SignatureBuilder sigBuilder = new SignatureBuilder();
            sigBuilder.setRequestLine(request.getRequestLine().toString());

            for (Header header : request.getAllHeaders()) {
                sigBuilder.addHeader(header.getName(), header.getValue());
            }

            if (sigBuilder.getDate() == null) {
                sigBuilder.addDateNow();
                request.addHeader(Constants.HEADER_DATE, sigBuilder.getDate());
            }

            Authorization authorization = signer.sign(sigBuilder);
            this.lastAuthz = authorization;
            if (authorization != null) {
                return new BasicHeader(Constants.AUTHORIZATION, authorization.getHeaderValue());
            }
        }

        return null;
    }
}
