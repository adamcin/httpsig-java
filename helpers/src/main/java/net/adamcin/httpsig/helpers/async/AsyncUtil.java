package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.Response;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Signer;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.Future;

public final class AsyncUtil {

    static final String REQUEST_LINE_FORMAT = "%s %s HTTP/1.1";

    /**
     * Attaches the provided {@link Signer} to the {@link AsyncHttpClient} as a signature calculator.
     * It is expected that key rotation and {@link net.adamcin.httpsig.api.Challenge} management is outside the scope
     * of this method, so only the {@link net.adamcin.httpsig.api.Keychain#currentKey()} will be used, and signature
     * content will be built according to the last {@link net.adamcin.httpsig.api.Challenge} provided to the
     * {@link Signer#rotateKeys(net.adamcin.httpsig.api.Challenge)} method.
     *
     * @see #login(com.ning.http.client.AsyncHttpClient, net.adamcin.httpsig.api.Signer, com.ning.http.client.Request)
     * @param client the {@link AsyncHttpClient} to use for
     * @param signer the {@link Signer} to use for authentication. It's keys must be rotated separately.
     */
    public static void enableAuth(final AsyncHttpClient client, final Signer signer) {
        client.setSignatureCalculator(new AsyncSignatureCalculator(signer));
    }

    /**
     * Executes and replays a login request until one is found which satisfies the
     * {@link net.adamcin.httpsig.api.Challenge} being returned by the server, or until there are no more keys in the
     * keychain.
     * @param client the {@link AsyncHttpClient} to which the {@link Signer} will be attached
     * @param signer the {@link Signer} used for login and subsequent signature authentication
     * @param loginRequest the login {@link Request} to be executed and replayed while rotating the keychain
     * @return a {@link Future} expecting a {@link Response}
     * @throws IOException if a request throws an exception
     */
    public static Future<Response> login(final AsyncHttpClient client,
                                         final Signer signer,
                                         final Request loginRequest)
            throws IOException {

        return login(client, signer, loginRequest, new AsyncCompletionHandler<Response>() {
            @Override
            public Response onCompleted(Response response) throws Exception {
                return response;
            }
        });
    }

    /**
     * Executes and replays a login request until one is found which satisfies the
     * {@link net.adamcin.httpsig.api.Challenge} being returned by the server, or until there are no more keys in the
     * keychain.
     * @param client the {@link AsyncHttpClient} to which the {@link Signer} will be attached
     * @param signer the {@link Signer} used for login and subsequent signature authentication
     * @param loginRequest the login {@link Request} to be executed and replayed while rotating the keychain
     * @param responseHandler an {@link AsyncCompletionHandler} of type {@code T}
     * @param <T> type parameter for completion handler
     * @return a {@link Future} of type {@code T}
     * @throws IOException if thrown by a login request
     */
    public static <T> Future<T> login(final AsyncHttpClient client,
                             final Signer signer,
                             final Request loginRequest,
                             AsyncCompletionHandler<T> responseHandler) throws IOException {

        final AsyncHttpClientConfig.Builder configBuilder = new AsyncHttpClientConfig.Builder(client.getConfig());
        configBuilder.addResponseFilter(new RotateAndReplayResponseFilter(signer));
        AsyncHttpClient loginClient = new AsyncHttpClient(configBuilder.build());

        enableAuth(loginClient, signer);
        Future<T> response = loginClient.executeRequest(loginClient
                                                                .prepareRequest(loginRequest)
                                                                .setUrl(loginRequest.getUrl()).build(),
                                                        responseHandler);
        enableAuth(client, signer);
        return response;
    }

    public static String getRequestLine(Request request, String requestLineFormat) {
        String path = "";
        try {
            URL url = new URL(request.getRawUrl());
            path = url.getPath() + (url.getQuery() != null ? "?" + url.getQuery() : "");
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        return String.format(requestLineFormat != null ? requestLineFormat : REQUEST_LINE_FORMAT, request.getMethod(), path);
    }

    public static void calculateSignature(Signer signer, Request request, RequestBuilderBase<?> requestBuilder, String requestLineFormat) {
        SignatureBuilder sigBuilder = new SignatureBuilder();

        sigBuilder.setRequestLine(AsyncUtil.getRequestLine(request, requestLineFormat));
        for (FluentCaseInsensitiveStringsMap.Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
            for (String value : entry.getValue()) {
                sigBuilder.addHeader(entry.getKey(), value);
            }
        }

        if (sigBuilder.getDate() == null) {
            sigBuilder.addDateNow();
            requestBuilder.addHeader(Constants.HEADER_DATE, sigBuilder.getDate());
        }

        Authorization authz = signer.sign(sigBuilder);
        if (authz != null) {
            requestBuilder.setHeader(Constants.AUTHORIZATION, authz.getHeaderValue());
        }
    }

    private AsyncUtil() {
    }
}
