package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.Request;
import net.adamcin.httpsig.api.KeyIdentifier;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.Signer;

public final class AsyncUtil {

    public static KeyRotationDecorator enableAuth(final AsyncHttpClient client, final Keychain keychain, final
                                                  KeyIdentifier keyIdentifier, final String requestLineFormat) {
        final Signer signer = new Signer(keychain, keyIdentifier);
        client.setSignatureCalculator(new AsyncSignatureCalculator(signer, requestLineFormat));
        return new KeyRotationDecorator() {
            public <T> AsyncCompletionHandler<T> decorate(Request request, AsyncCompletionHandler<T> delegatee) {
                return new KeyRotationHandler<T>(signer, request, delegatee);
            }
        };
    }

    private AsyncUtil() {
    }
}
