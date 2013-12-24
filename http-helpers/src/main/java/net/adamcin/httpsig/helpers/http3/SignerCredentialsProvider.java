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

package net.adamcin.httpsig.helpers.http3;

import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.Signer;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.auth.AuthScheme;
import org.apache.commons.httpclient.auth.CredentialsNotAvailableException;
import org.apache.commons.httpclient.auth.CredentialsProvider;

public final class SignerCredentialsProvider implements CredentialsProvider {

    private final Signer signer;
    private final CredentialsProvider delegatee;

    public SignerCredentialsProvider(Signer signer, CredentialsProvider delegatee) {
        this.signer = signer;
        this.delegatee = delegatee;
    }

    public CredentialsProvider getDelegatee() {
        return delegatee;
    }

    public Credentials getCredentials(AuthScheme scheme, String host, int port, boolean proxy)
            throws CredentialsNotAvailableException {

        if (Constants.SCHEME.equals(scheme.getSchemeName())) {
            if (signer == null) {
                throw new CredentialsNotAvailableException("SSHKey Signer not available");
            } else {
                return new SignerCredentials(signer);
            }
        } else {
            if (this.delegatee != null) {
                return this.delegatee.getCredentials(scheme, host, port, proxy);
            }
        }
        return null;
    }
}
