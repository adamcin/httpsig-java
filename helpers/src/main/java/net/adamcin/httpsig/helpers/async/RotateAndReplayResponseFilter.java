package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilder;
import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterException;
import com.ning.http.client.filter.ResponseFilter;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.Signer;

import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 12/9/13
 * Time: 6:47 PM
 * To change this template use File | Settings | File Templates.
 */
public class RotateAndReplayResponseFilter implements ResponseFilter {

    private final Signer signer;
    private final String requestLineFormat;

    public RotateAndReplayResponseFilter(Signer signer, String requestLineFormat) {
        this.signer = signer;
        this.requestLineFormat = requestLineFormat;
    }

    public FilterContext filter(FilterContext ctx) throws FilterException {
        if (ctx.getResponseStatus().getStatusCode() == 401) {
                        Challenge challenge = null;
            for (String header : ctx.getResponseHeaders().getHeaders().get(Constants.CHALLENGE)) {
                challenge = Challenge.parseChallenge(header);
                if (challenge != null) {
                    break;
                }
            }

            if (challenge != null) {
                Authorization authorization = null;
                Request request = ctx.getRequest();
                for (FluentCaseInsensitiveStringsMap.Entry<String, List<String>> headersEntry : request.getHeaders()) {
                    if (headersEntry.getKey().equalsIgnoreCase(Constants.AUTHORIZATION)) {
                        for (String header : headersEntry.getValue()) {
                            authorization = Authorization.parse(header);
                            if (authorization != null) {
                                //request.getHeaders().delete(Constants.AUTHORIZATION);
                                break;
                            }
                        }
                    }
                }


                boolean replay = signer.rotateKeys(challenge, authorization);
                RequestBuilder builder = new RequestBuilder(request);
                AsyncUtil.calculateSignature(signer, request, builder, requestLineFormat);

                return new FilterContext.FilterContextBuilder(ctx)
                        .replayRequest(replay)
                        .request(builder.build())
                        .build();
            }
        }

        return ctx;

    }
}
