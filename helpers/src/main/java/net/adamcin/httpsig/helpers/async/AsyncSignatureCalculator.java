package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.SignatureCalculator;
import net.adamcin.httpsig.api.Signer;

/**
 *
 */
public class AsyncSignatureCalculator implements SignatureCalculator {
    private final Signer signer;
    private final String requestLineFormat;

    public AsyncSignatureCalculator(Signer signer, String requestLineFormat) {
        this.signer = signer;
        this.requestLineFormat = requestLineFormat != null ? requestLineFormat : AsyncUtil.DEFAULT_REQUEST_LINE_FORMAT;
    }

    public void calculateAndAddSignature(String url, Request request, RequestBuilderBase<?> requestBuilder) {
        AsyncUtil.calculateSignature(this.signer, request, requestBuilder, this.requestLineFormat);
    }
}
