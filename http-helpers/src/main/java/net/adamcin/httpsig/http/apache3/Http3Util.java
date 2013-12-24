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

import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.KeyId;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.Signer;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.CredentialsProvider;
import org.apache.commons.httpclient.params.DefaultHttpParams;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class Http3Util {

    public static void enableAuth(HttpClient client, Keychain keychain, KeyId keyId) {
        Signer signer = new Signer(keychain, keyId);
        CredentialsProvider credProvider =
            (CredentialsProvider) client.getParams()
                    .getParameter(CredentialsProvider.PROVIDER);

        CredentialsProvider newProvider;
        if (credProvider instanceof SignerCredentialsProvider) {
            newProvider = new SignerCredentialsProvider(signer,
                                                        ((SignerCredentialsProvider) credProvider).getDelegatee());
        } else {
            newProvider = new SignerCredentialsProvider(signer, credProvider);
        }

        client.getParams().setParameter(CredentialsProvider.PROVIDER, newProvider);
        AuthPolicy.registerAuthScheme(Constants.SCHEME, Http3SignatureAuthScheme.class);
        List<String> schemes = new ArrayList<String>();
        schemes.add(Constants.SCHEME);

        Collection authSchemePriority = (Collection) DefaultHttpParams.getDefaultParams().getParameter(AuthPolicy.AUTH_SCHEME_PRIORITY);
        if (authSchemePriority != null) {
            schemes.addAll(authSchemePriority);
        }
        client.getParams().setParameter(AuthPolicy.AUTH_SCHEME_PRIORITY, schemes);
    }

    private Http3Util() {
    }
}
