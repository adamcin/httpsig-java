package net.adamcin.httpsig.helpers.http4;

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
