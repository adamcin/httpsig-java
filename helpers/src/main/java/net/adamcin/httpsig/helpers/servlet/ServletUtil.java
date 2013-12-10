package net.adamcin.httpsig.helpers.servlet;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.SignatureBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 12/9/13
 * Time: 3:58 PM
 * To change this template use File | Settings | File Templates.
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
        signatureBuilder.setRequestLine(
                String.format(
                        "%s %s %s",
                        request.getMethod(), request.getRequestURI(), request.getProtocol()
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

    public static void sendChallenge(HttpServletRequest req, HttpServletResponse resp, Challenge challenge)
            throws ServletException, IOException {

        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        resp.setHeader(Constants.CHALLENGE, challenge.getHeaderValue());
        resp.flushBuffer();
    }
}
