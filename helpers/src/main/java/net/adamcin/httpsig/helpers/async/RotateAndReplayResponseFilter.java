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
 * Implementation of {@link ResponseFilter} which calls
 * {@link Signer#rotateKeys(net.adamcin.httpsig.api.Challenge, net.adamcin.httpsig.api.Authorization)} so long as the
 * response is a 401 or no keys are left to try.
 */
public class RotateAndReplayResponseFilter implements ResponseFilter {

    private final Signer signer;

    public RotateAndReplayResponseFilter(Signer signer) {
        this.signer = signer;
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
                                break;
                            }
                        }
                    }
                }


                boolean replay = signer.rotateKeys(challenge, authorization);
                if (!replay) {
                    signer.rotateKeys(challenge);
                    return ctx;
                }

                RequestBuilder builder = new RequestBuilder(request);
                AsyncUtil.calculateSignature(signer, request, builder, AsyncUtil.REQUEST_LINE_FORMAT);

                return new FilterContext.FilterContextBuilder(ctx)
                        .replayRequest(replay)
                        .request(builder.build())
                        .build();
            }
        }

        return ctx;

    }
}
