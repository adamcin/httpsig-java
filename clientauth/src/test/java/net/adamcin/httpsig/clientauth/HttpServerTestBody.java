package net.adamcin.httpsig.clientauth;

import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Base64;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
public abstract class HttpServerTestBody extends TestBody {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpServerTestBody.class);

    protected Server server = null;
    protected ServletHolder servletHolder = new ServletHolder(new NotFoundServlet());

    protected HttpServerTestBody() {
        server = new Server(0);
        ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(servletHolder, "/*");
        server.setHandler(handler);
        try {
            server.start();
        } catch (Exception e) {
            LOGGER.error("[HttpServerTestBody] server failed to start.");
        }
    }

    protected void setServlet(Servlet servlet) throws Exception {
        servletHolder.setServlet(servlet);
    }

    protected Integer getPort() {
        if (server.getConnectors().length > 0) {
            return ((ServerConnector) server.getConnectors()[0]).getLocalPort();
        } else {
            return null;
        }
    }

    @Override
    protected void cleanUp() {
        if (server != null) {
            try {
                server.stop();
            } catch (Exception e) {
                LOGGER.error("[cleanUp] failed to stop jetty server", e);
            }
        }
    }

    @SuppressWarnings("serial")
    public static class OkServlet extends HttpServlet {

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/html");
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.getWriter().println("<h1>Ok</h1>");
        }
    }

    @SuppressWarnings("serial")
    public static class NotFoundServlet extends HttpServlet {

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/html");
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.getWriter().println("<h1>Not Found</h1>");
        }
    }

    @SuppressWarnings("serial")
    public static class AdminServlet extends HttpServlet {
        public static final String REALM = AdminServlet.class.getName();
        public static final String LOGIN_ID = "admin";
        public static final String COOKIE_NAME = "authenticated";

        private final Map<String, Challenge> sessions = Collections.synchronizedMap(new HashMap<String, Challenge>());

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            Enumeration<String> headerNames = req.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                Enumeration<String> headers = req.getHeaders(headerName);
                while (headers.hasMoreElements()) {
                    LOGGER.debug("[doGet][header] {}: {}", headerName, headers.nextElement());
                }
            }

            resp.setContentType("text/html");
            if (!handleAuthentication(req, resp)) {
                LOGGER.info("[doGet] responding with OK");
                resp.setStatus(HttpServletResponse.SC_OK);
                resp.getWriter().println("<h1>Ok</h1>");
                resp.flushBuffer();
            }

            LOGGER.info("[doGet] done");
        }

        private boolean handleAuthentication(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            if (req.getCookies() != null) {
                for (Cookie cookie : req.getCookies()) {
                    LOGGER.debug("[handleAuthentication] cookie: {}={}", cookie.getName(), cookie.getValue());
                    if (COOKIE_NAME.equals(cookie.getName())) {
                        return false;
                    }
                }
            }

            Authorization authorization = getLogin(req);
            if (authorization != null && sessions.containsKey(authorization.getToken())) {
                Challenge challenge = null;
                synchronized (this.sessions) {
                    challenge = this.sessions.remove(authorization.getToken());
                }
                Verifier verifier = AuthorizedKeys.newVerifier(KeyTestUtil.getAuthorizedKeysFile());
                if (challenge != null && verifier.verify(challenge, authorization)) {
                    resp.addCookie(new Cookie(COOKIE_NAME, "true"));
                    return false;
                }
            }

            Challenge challenge = createChallenge(req);
            if (challenge != null) {
                sendChallenge(req, resp, challenge);
            } else {
                sendForbidden(req, resp);
            }

            return true;
        }

        private Authorization getLogin(HttpServletRequest req) {
            String authHeader = req.getHeader(Constants.AUTHORIZATION);
            if (authHeader == null || authHeader.length() == 0) {
                return null;
            } else {
                LOGGER.info("[getLogin] authorization={}", authHeader);
                return Authorization.parse(authHeader);
            }
        }

        private Challenge createChallenge(HttpServletRequest req) throws IOException {
            String loginId = req.getHeader(Constants.SSHKEY_LOGIN_ID);
            if (LOGIN_ID.equals(loginId)) {
                Verifier verifier = AuthorizedKeys.newVerifier(KeyTestUtil.getAuthorizedKeysFile());
                String fingerprint = selectFingerprint(req, verifier);
                if (fingerprint != null) {
                    String host = req.getHeader(Constants.HOST) != null ? req.getHeader(Constants.HOST) : "";
                    String userAgent = req.getHeader(Constants.USER_AGENT) != null ? req.getHeader(
                            Constants.USER_AGENT
                    ) : "";
                    String nonce = Base64.toBase64String(
                            (loginId + host + userAgent + Long.toString(System.currentTimeMillis())).getBytes(
                                    Constants.CHARSET
                            )
                    );
                    Challenge challenge = new Challenge(REALM, fingerprint, nonce, host, userAgent, verifier.getKeychain().algorithms());
                    LOGGER.debug("[createChallenge] challenge: {}", challenge);
                    synchronized (this.sessions) {
                        this.sessions.put(nonce, challenge);
                    }

                    return challenge;
                }
            }

            return null;
        }

        private String selectFingerprint(HttpServletRequest req, Verifier verifier) {
            List<String> _fingerprints = new ArrayList<String>();
            Enumeration fingerprints = req.getHeaders(Constants.SSHKEY_FINGERPRINT);
            if (fingerprints != null) {
                while (fingerprints.hasMoreElements()) {
                    String fingerprint = (String) fingerprints.nextElement();
                    _fingerprints.add(fingerprint);
                }
            }
            return verifier.select(_fingerprints);
        }

        private void sendChallenge(HttpServletRequest req, HttpServletResponse resp, Challenge challenge)
                throws ServletException, IOException {

            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.setHeader(Constants.CHALLENGE, challenge.getHeaderValue());
            resp.flushBuffer();
        }

        private void sendForbidden(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getWriter().println("<h1>Forbidden</h1>");
            resp.flushBuffer();
        }
    }

}
