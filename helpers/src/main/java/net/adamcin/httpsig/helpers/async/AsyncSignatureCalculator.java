package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.SignatureCalculator;
import net.adamcin.httpsig.api.Signer;

/**
 * Implementation of {@link SignatureCalculator} using a {@link Signer}
 */
public class AsyncSignatureCalculator implements SignatureCalculator {
    private final Signer signer;

    public AsyncSignatureCalculator(Signer signer) {
        this.signer = signer;
    }

    /**
     * {@inheritDoc}
     */
    public void calculateAndAddSignature(String url, Request request, RequestBuilderBase<?> requestBuilder) {
        AsyncUtil.calculateSignature(this.signer, request, requestBuilder, AsyncUtil.REQUEST_LINE_FORMAT);
    }
}
