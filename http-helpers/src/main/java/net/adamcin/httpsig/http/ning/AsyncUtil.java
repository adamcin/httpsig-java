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

package net.adamcin.httpsig.http.ning;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.Response;
import com.ning.http.client.SignatureCalculator;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.RequestContent;
import net.adamcin.httpsig.api.Signer;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.Future;

public final class AsyncUtil {

    /**
     * Attaches the provided {@link Signer} to the {@link AsyncHttpClient} as a signature calculator.
     * It is expected that key rotation and {@link net.adamcin.httpsig.api.Challenge} management is outside the scope
     * of this method, so only the {@link net.adamcin.httpsig.api.Keychain#currentKey()} will be used, and signature
     * content will be built according to the last {@link net.adamcin.httpsig.api.Challenge} provided to the
     * {@link Signer#rotateKeys(net.adamcin.httpsig.api.Challenge)} method.
     *
     * @since 1.0.0
     *
     * @see #login(com.ning.http.client.AsyncHttpClient, net.adamcin.httpsig.api.Signer, com.ning.http.client.Request)
     * @param client the {@link AsyncHttpClient} to use for
     * @param signer the {@link Signer} to use for authentication. It's keys must be rotated separately.
     */
    public static void enableAuth(final AsyncHttpClient client, final Signer signer) {
        enableAuth(client, signer, null);
    }

    /**
     * Attaches the provided {@link Signer} to the {@link AsyncHttpClient} as a signature calculator.
     * It is expected that key rotation and {@link net.adamcin.httpsig.api.Challenge} management is outside the scope
     * of this method, so only the {@link net.adamcin.httpsig.api.Keychain#currentKey()} will be used, and signature
     * content will be built according to the last {@link net.adamcin.httpsig.api.Challenge} provided to the
     * {@link Signer#rotateKeys(net.adamcin.httpsig.api.Challenge)} method.
     *
     * @since 1.0.4
     *
     * @see #login(com.ning.http.client.AsyncHttpClient, net.adamcin.httpsig.api.Signer, com.ning.http.client.Request)
     * @param client the {@link AsyncHttpClient} to use for
     * @param signer the {@link Signer} to use for authentication. It's keys must be rotated separately.
     * @param calcBefore provide another {@link SignatureCalculator} to call (such as a Content-MD5 generator) prior to
     *                   generating the signature for authentication.
     */
    public static void enableAuth(final AsyncHttpClient client, final Signer signer, final SignatureCalculator calcBefore) {
        client.setSignatureCalculator(new AsyncSignatureCalculator(signer, calcBefore));
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
     *
     * @since 1.0.0
     *
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
        return login(client, signer, loginRequest, responseHandler, null);
    }

    /**
     * Executes and replays a login request until one is found which satisfies the
     * {@link net.adamcin.httpsig.api.Challenge} being returned by the server, or until there are no more keys in the
     * keychain.
     *
     * @since 1.0.4
     *
     * @param client the {@link AsyncHttpClient} to which the {@link Signer} will be attached
     * @param signer the {@link Signer} used for login and subsequent signature authentication
     * @param loginRequest the login {@link Request} to be executed and replayed while rotating the keychain
     * @param responseHandler an {@link AsyncCompletionHandler} of type {@code T}
     * @param calcBefore provide another {@link SignatureCalculator} to call (such as a Content-MD5 generator) prior to
     *                   generating the signature for authentication.
     * @param <T> type parameter for completion handler
     * @return a {@link Future} of type {@code T}
     * @throws IOException if thrown by a login request
     */
    public static <T> Future<T> login(final AsyncHttpClient client,
                             final Signer signer,
                             final Request loginRequest,
                             final AsyncCompletionHandler<T> responseHandler,
                             final SignatureCalculator calcBefore) throws IOException {

        final AsyncHttpClientConfig.Builder configBuilder = new AsyncHttpClientConfig.Builder(client.getConfig());
        configBuilder.addResponseFilter(new RotateAndReplayResponseFilter(signer));
        AsyncHttpClient loginClient = new AsyncHttpClient(configBuilder.build());

        enableAuth(loginClient, signer, calcBefore);
        Future<T> response = loginClient.executeRequest(loginClient
                                                                .prepareRequest(loginRequest)
                                                                .setUrl(loginRequest.getUrl()).build(),
                                                        responseHandler);
        enableAuth(client, signer, calcBefore);
        return response;
    }

    protected static String getRequestPath(Request request) {
        try {
            URL url = new URL(request.getUrl());
            return url.getPath() + (url.getQuery() != null ? "?" + url.getQuery() : "");
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        return null;
    }

    public static void calculateSignature(Signer signer, Request request, RequestBuilderBase<?> requestBuilder) {
        RequestContent.Builder sigBuilder = new RequestContent.Builder();

        sigBuilder.setRequestTarget(request.getMethod(), getRequestPath(request));
        for (FluentCaseInsensitiveStringsMap.Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
            for (String value : entry.getValue()) {
                sigBuilder.addHeader(entry.getKey(), value);
            }
        }

        if (sigBuilder.build().getDate() == null) {
            sigBuilder.addDateNow();
            requestBuilder.addHeader(Constants.HEADER_DATE, sigBuilder.build().getDate());
        }

        Authorization authz = signer.sign(sigBuilder.build());
        if (authz != null) {
            requestBuilder.setHeader(Constants.AUTHORIZATION, authz.getHeaderValue());
        }
    }

    private AsyncUtil() {
    }
}
