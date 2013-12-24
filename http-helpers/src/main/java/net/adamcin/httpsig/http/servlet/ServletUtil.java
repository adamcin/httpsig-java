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

package net.adamcin.httpsig.http.servlet;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.SignatureBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 */
public final class ServletUtil {

    private ServletUtil() {
    }

    public static Authorization getAuthorization(HttpServletRequest request) {
        Enumeration headerValues = request.getHeaders(Constants.AUTHORIZATION);
        while (headerValues.hasMoreElements()) {
            String headerValue = (String) headerValues.nextElement();
            Authorization authorization = Authorization.parse(headerValue);
            if (authorization != null) {
                return authorization;
            }
        }

        return null;
    }

    public static SignatureBuilder getSignatureBuilder(HttpServletRequest request) {
        return getSignatureBuilder(request, null);
    }

    public static SignatureBuilder getSignatureBuilder(HttpServletRequest request, Collection<String> ignoreHeaders) {
        final Set<String> _ignore = new HashSet<String>();

        if (ignoreHeaders != null) {
            for (String ignore : ignoreHeaders) {
                _ignore.add(ignore.toLowerCase());
            }
        }

        SignatureBuilder signatureBuilder = new SignatureBuilder();
        String path = request.getRequestURI() + (request.getQueryString() != null ? "?" + request.getQueryString() : "");

        signatureBuilder.setRequestLine(
                String.format(
                        "%s %s %s",
                        request.getMethod(), path, request.getProtocol()
                )
        );

        Enumeration headerNames = request.getHeaderNames();

        while (headerNames.hasMoreElements()) {
            String headerName = (String) headerNames.nextElement();
            if (!_ignore.contains(headerName.toLowerCase())) {
                Enumeration headerValues = request.getHeaders(headerName);
                while (headerValues.hasMoreElements()) {
                    String headerValue = (String) headerValues.nextElement();
                    signatureBuilder.addHeader(headerName, headerValue);
                }
            }
        }

        return signatureBuilder;
    }

    public static boolean sendChallenge(HttpServletResponse resp, Challenge challenge) throws IOException {
        if (!resp.isCommitted()) {
            resp.resetBuffer();
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.setHeader(Constants.CHALLENGE, challenge.getHeaderValue());
            resp.flushBuffer();
            return true;
        }
        return false;
    }
}
