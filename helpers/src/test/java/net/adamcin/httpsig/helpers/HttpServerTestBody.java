package net.adamcin.httpsig.helpers;

import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.KeyIdentifier;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.helpers.servlet.ServletUtil;
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
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.List;

/**
 *
 */
public abstract class HttpServerTestBody extends TestBody {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpServerTestBody.class);

    protected Server server = null;
    protected ServletHolder servletHolder = new ServletHolder(new NotFoundServlet());
    protected KeyIdentifier keyIdentifier = null;

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

    protected String getAbsoluteUrl(String requestUrl) {
        return String.format("http://localhost:%s%s", getPort(), requestUrl);
    }

    public KeyIdentifier getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(KeyIdentifier keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
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
    public class AdminServlet extends HttpServlet {
        public final String REALM = getClass().getName();

        private final List<String> headers;
        private final KeyIdentifier keyIdentifier;

        private Keychain keychain;
        private Challenge challenge;

        public AdminServlet(List<String> headers) {
            super();
            this.headers = headers;
            this.keyIdentifier = getKeyIdentifier();
        }

        protected Keychain getKeychain() throws IOException {
            if (this.keychain == null) {
                this.keychain = AuthorizedKeys.newKeychain(KeyTestUtil.getAuthorizedKeysFile());
            }
            return this.keychain;
        }

        protected Challenge getChallenge() throws IOException {
            if (this.challenge == null) {
                this.challenge = new Challenge(REALM, this.headers, getKeychain().getAlgorithms());
            }
            return this.challenge;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            Enumeration<String> headerNames = req.getHeaderNames();
            if (true) {
                while (headerNames.hasMoreElements()) {
                    String headerName = headerNames.nextElement();
                    Enumeration<String> headers = req.getHeaders(headerName);
                    while (headers.hasMoreElements()) {
                        LOGGER.info("[doGet][header] {}: {}", headerName, headers.nextElement());
                    }
                }
                LOGGER.info("[doGet] no more headers");
            }

            resp.setContentType("text/html");
            if (!handleAuthentication(req, resp)) {
                LOGGER.info("[doGet] responding with OK");
                resp.setStatus(HttpServletResponse.SC_OK);
                resp.getWriter().println("<h1>Ok</h1>");
                resp.flushBuffer();
            }
        }

        private boolean handleAuthentication(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            Authorization authorization = ServletUtil.getAuthorization(req);
            if (authorization != null) {
                Verifier verifier = new Verifier(this.getKeychain(), this.keyIdentifier);
                SignatureBuilder sigBuilder = ServletUtil.getSignatureBuilder(req);

                if (verifier.verify(getChallenge(), sigBuilder, authorization)) {
                    return false;
                }
            }

            ServletUtil.sendChallenge(req, resp, getChallenge());

            return true;
        }

    }

}
