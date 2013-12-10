package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.KeyIdentifier;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Signer;

import java.net.URL;
import java.util.List;

public final class AsyncUtil {

    static final String DEFAULT_REQUEST_LINE_FORMAT = "%s %s HTTP/1.1";

    public static AsyncHttpClient getAsyncClient(final Keychain keychain, final KeyIdentifier keyIdentifier) {
        return getAsyncClient(keychain, keyIdentifier, null);
    }

    public static AsyncHttpClient getAsyncClient(final Keychain keychain, final KeyIdentifier keyIdentifier,
                                                      final String requestLineFormat) {

        return getAsyncClient(keychain, keyIdentifier, requestLineFormat, new AsyncHttpClientConfig.Builder());
    }

    public static AsyncHttpClient getAsyncClient(final Keychain keychain, final KeyIdentifier keyIdentifier,
                                                 final String requestLineFormat,
                                                 final AsyncHttpClientConfig.Builder configBuilder) {
        final Signer signer = new Signer(keychain, keyIdentifier);

        final String _format = requestLineFormat != null ? requestLineFormat : DEFAULT_REQUEST_LINE_FORMAT;
        configBuilder.addResponseFilter(new RotateAndReplayResponseFilter(signer, _format));
        AsyncHttpClient client = new AsyncHttpClient(configBuilder.build());
        client.setSignatureCalculator(new AsyncSignatureCalculator(signer, _format));
        return client;
    }

    public static String getRequestLine(Request request, String requestLineFormat) {
        String path = "";
        try {
            URL url = new URL(request.getRawUrl());
            path = url.getPath() + (url.getQuery() != null ? "?" + url.getQuery() : "");
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

        return String.format(requestLineFormat != null ? requestLineFormat : DEFAULT_REQUEST_LINE_FORMAT, request.getMethod(), path);
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

        System.out.println("client: " + sigBuilder.getRequestLine());
        Authorization authz = signer.sign(sigBuilder);
        if (authz != null) {
            requestBuilder.setHeader(Constants.AUTHORIZATION, authz.getHeaderValue());
        }
    }

    private AsyncUtil() {
    }
}
