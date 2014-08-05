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
                challenge = Challenge.parse(header);
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
                AsyncUtil.calculateSignature(signer, request, builder);

                return new FilterContext.FilterContextBuilder(ctx)
                        .replayRequest(replay)
                        .request(builder.build())
                        .build();
            }
        }

        return ctx;

    }
}
