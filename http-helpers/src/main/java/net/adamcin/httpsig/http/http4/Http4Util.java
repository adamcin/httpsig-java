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

package net.adamcin.httpsig.http.http4;

import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.KeyIdentifier;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.Signer;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.params.HttpParams;

import java.util.Arrays;

public final class Http4Util {

    public static void enableAuth(final AbstractHttpClient client, final Keychain keychain, final KeyIdentifier keyIdentifier) {
        if (client == null) {
            throw new NullPointerException("client");
        }

        if (keychain == null) {
            throw new NullPointerException("keychain");
        }

        client.getAuthSchemes().register(Constants.SCHEME, new AuthSchemeFactory() {
            public AuthScheme newInstance(HttpParams params) {
                return new Http4SignatureAuthScheme();
            }
        });

        Signer signer = new Signer(keychain, keyIdentifier);
        client.getCredentialsProvider().setCredentials(AuthScope.ANY, new SignerCredentials(signer));
        client.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF,
                                        Arrays.asList(Constants.SCHEME));

        HttpClientParams.setAuthenticating(client.getParams(), true);
    }

    private Http4Util() {
    }

}
