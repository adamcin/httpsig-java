package net.adamcin.httpsig.clientauth.async;

import com.ning.http.client.AsyncHttpClient;


public interface RequestBuilderDecorator {

    AsyncHttpClient.BoundRequestBuilder decorate(AsyncHttpClient.BoundRequestBuilder builder);
}
