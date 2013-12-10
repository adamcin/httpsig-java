package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.Request;
import com.ning.http.client.Response;
import com.ning.http.util.AsyncHttpProviderUtils;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.Signer;

import java.net.URL;

public final class KeyRotationHandler<T> extends AsyncCompletionHandler<T> {
    private final Signer signer;
    private final Request request;
    private final AsyncCompletionHandler<T> delegatee;

    public KeyRotationHandler(Signer signer, Request request, AsyncCompletionHandler<T> delegatee) {
        this.signer = signer;
        this.request = request;
        this.delegatee = delegatee;
    }

    @Override
    public T onCompleted(Response response) throws Exception {
        if (response.getStatusCode() == 401) {
            Challenge challenge = null;
            for (String header : response.getHeaders(Constants.CHALLENGE)) {
                challenge = Challenge.parseChallenge(header);
                if (challenge != null) {
                    break;
                }
            }

            if (challenge != null) {
                Authorization authorization = null;
                for (String header : request.getHeaders().get(Constants.AUTHORIZATION)) {
                    authorization = Authorization.parse(header);
                    if (authorization != null) {
                        break;
                    }
                }

                signer.rotateKeys(challenge, authorization);
            }
        }

        return delegatee.onCompleted(response);
    }
}
