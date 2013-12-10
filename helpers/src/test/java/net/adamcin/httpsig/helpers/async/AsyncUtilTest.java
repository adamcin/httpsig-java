package net.adamcin.httpsig.helpers.async;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.Request;
import com.ning.http.client.Response;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.helpers.HttpServerTestBody;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.httpsig.jce.JCEKey;
import net.adamcin.httpsig.jce.KeyFormat;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.*;

public class AsyncUtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AsyncUtilTest.class);

    private static final AsyncCompletionHandler<Boolean> DEFAULT_HANDLER = new AsyncCompletionHandler<Boolean>() {
        @Override
        public Boolean onCompleted(Response response) throws Exception {
            return response.getStatusCode() == 200;
        }
    };

    @Test
    public void testLogin() {

        TestBody.test(new HttpServerTestBody() {
                    @Override
                    protected void execute() throws Exception {
                        setServlet(new AdminServlet(Arrays.asList(Constants.HEADER_REQUEST_LINE, Constants.HEADER_DATE), AuthorizedKeys.newKeychain(KeyTestUtil.getAuthorizedKeysFile()), null));
                        KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");

                        DefaultKeychain provider = new DefaultKeychain();
                        provider.add(new JCEKey(KeyFormat.SSH_RSA, keyPair));

                        // TODO find out why connection pooling breaks the last request
                        //AsyncHttpClient client = new AsyncHttpClient(new AsyncHttpClientConfig.Builder().setAllowPoolingConnection(false).build());
                        AsyncHttpClient client = AsyncUtil.getAsyncClient(provider, null);

                        Request request = client.prepareGet(
                                String.format("http://localhost:%d/index.html?foo=bar", getPort())).build();

                        AsyncCompletionHandler<Boolean> handler = DEFAULT_HANDLER;

                        assertTrue("login should be successful", client.executeRequest(request, handler).get());

                    }
                }
        );

    }
}
