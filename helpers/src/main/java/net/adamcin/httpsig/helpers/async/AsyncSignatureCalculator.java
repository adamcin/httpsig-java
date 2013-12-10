package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.SignatureCalculator;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Signer;

import java.util.List;

/**
 *
 */
public class AsyncSignatureCalculator implements SignatureCalculator {
    private static final String DEFAULT_FORMAT = "%s %s HTTP/1.1";
    private final Signer signer;
    private final String requestLineFormat;

    public AsyncSignatureCalculator(Signer signer, String requestLineFormat) {
        this.signer = signer;
        this.requestLineFormat = requestLineFormat != null ? requestLineFormat : DEFAULT_FORMAT;
    }

    public void calculateAndAddSignature(String url, Request request, RequestBuilderBase<?> requestBuilder) {
        SignatureBuilder sigBuilder = new SignatureBuilder();

        sigBuilder.setRequestLine(String.format(requestLineFormat, request.getMethod(), request.getRawUrl()));
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
            requestBuilder.addHeader(Constants.AUTHORIZATION, authz.getHeaderValue());
        }
    }
}
