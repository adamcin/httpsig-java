package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.Request;

/**
 * Decorates {@link AsyncCompletionHandler}s with wrapping logic to reattempt failed signature authentication
 * after rotating keys in the underlying signer.
 */
public interface KeyRotationDecorator {

    <T> AsyncCompletionHandler<T> decorate(Request request, AsyncCompletionHandler<T> delegatee);

}
