package net.adamcin.httpsig.helpers.http3;

import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.helpers.HttpServerTestBody;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.httpsig.jce.JCEKey;
import net.adamcin.httpsig.jce.KeyFormat;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class Http3UtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(Http3UtilTest.class);


    @Test
    public void testLogin() {
        TestBody.test(new HttpServerTestBody() {

            @Override protected void execute() throws Exception {
                List<String> headers = Arrays.asList(
                        Constants.HEADER_REQUEST_LINE,
                        Constants.HEADER_DATE);
                setServlet(new AdminServlet(headers));

                KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");

                DefaultKeychain provider = new DefaultKeychain();
                provider.add(new JCEKey(KeyFormat.SSH_RSA, keyPair));

                HttpClient client = new HttpClient();

                Http3Util.enableAuth(client, provider, getKeyIdentifier());
                HttpMethod request = new GetMethod(getAbsoluteUrl("/index.html?foo=bar"));
                try {
                    int status = client.executeMethod(request);
                    assertEquals("should return 200", 200, status);
                } finally {
                    request.releaseConnection();
                }
            }
        });
    }

    @Test
    public void testAllHeaders() {
        TestBody.test(new HttpServerTestBody() {
            @Override protected void execute() throws Exception {
                List<String> headers = Arrays.asList(
                        Constants.HEADER_REQUEST_LINE,
                        Constants.HEADER_DATE,
                        "x-test"
                );

                setServlet(new AdminServlet(headers));

                KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");

                DefaultKeychain provider = new DefaultKeychain();
                provider.add(new JCEKey(KeyFormat.SSH_RSA, keyPair));

                HttpClient client = new HttpClient();

                Http3Util.enableAuth(client, provider, getKeyIdentifier());
                HttpMethod request = new GetMethod(getAbsoluteUrl("/index.html?foo=bar"));
                request.addRequestHeader("x-test", "foo");
                try {
                    int status = client.executeMethod(request);
                    assertEquals("should return 200", 200, status);
                } finally {
                    request.releaseConnection();
                }
            }
        });
    }
}
