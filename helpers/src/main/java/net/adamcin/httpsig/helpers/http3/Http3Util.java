package net.adamcin.httpsig.helpers.http3;

import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.KeyIdentifier;
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

    public static void enableAuth(HttpClient client, Keychain keychain, KeyIdentifier keyIdentifier) {
        Signer signer = new Signer(keychain, keyIdentifier);
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
