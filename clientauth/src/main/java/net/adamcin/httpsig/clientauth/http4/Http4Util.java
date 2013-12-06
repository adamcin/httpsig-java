package net.adamcin.httpsig.clientauth.http4;

import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.Signer;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.util.Arrays;

public final class Http4Util {

    public static void enableAuth(final Signer signer, AbstractHttpClient client) {
        if (signer == null) {
            throw new NullPointerException("signer");
        }

        if (client == null) {
            throw new NullPointerException("client");
        }

        client.getAuthSchemes().register(Constants.SCHEME, new AuthSchemeFactory() {
            public AuthScheme newInstance(HttpParams params) {
                return new Http4SSHKeyAuthScheme();
            }
        });

        client.getCredentialsProvider().setCredentials(AuthScope.ANY, new SignerCredentials(signer));
        client.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF,
                                        Arrays.asList(Constants.SCHEME));

        HttpClientParams.setAuthenticating(client.getParams(), true);
    }

    public static void setHeaders(HttpUriRequest request, Signer signer, String loginId) {
        if (request != null) {

            request.removeHeaders(Constants.SSHKEY_LOGIN_ID);
            if (loginId != null) {
                request.setHeader(Constants.SSHKEY_LOGIN_ID, loginId);
            }

            request.removeHeaders(Constants.SSHKEY_FINGERPRINT);
            if (signer != null) {
                for (String fingerprint : signer.getFingerprints()) {
                    request.addHeader(Constants.SSHKEY_FINGERPRINT, fingerprint);
                }
            }
        }
    }

    public static boolean login(String loginUri, Signer signer, String loginId, int expectStatus,
                                AbstractHttpClient client,
                                HttpContext context)
            throws IOException {

        enableAuth(signer, client);
        HttpUriRequest request = new HttpGet(loginUri);
        setHeaders(request, signer, loginId);
        return client.execute(request, context).getStatusLine().getStatusCode() == expectStatus;
    }

    private Http4Util() {
    }

}
