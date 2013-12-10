package net.adamcin.httpsig.helpers.http4;

import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Signer;
import net.adamcin.httpsig.helpers.HttpServerTestBody;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.httpsig.jce.JCEKey;
import net.adamcin.httpsig.jce.KeyFormat;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.DefaultHttpClient;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;

import static org.junit.Assert.*;

public class Http4UtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(Http4UtilTest.class);


    @Test
    public void testLogin() {
        TestBody.test(new HttpServerTestBody() {
            @Override protected void execute() throws Exception {
                setServlet(new AdminServlet(
                        Constants.DEFAULT_HEADERS, AuthorizedKeys.newKeychain(
                        KeyTestUtil.getAuthorizedKeysFile()
                ), null));

                KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");

                DefaultKeychain provider = new DefaultKeychain();
                provider.add(new JCEKey(KeyFormat.SSH_RSA, keyPair));

                DefaultHttpClient client = new DefaultHttpClient();

                Http4Util.enableAuth(client, provider, null);
                HttpUriRequest request = new HttpGet(String.format("http://localhost:%d/index.html", getPort()));
                HttpResponse response = client.execute(request);

                assertEquals("should return 200", 200, response.getStatusLine().getStatusCode());

            }
        });
    }
}
