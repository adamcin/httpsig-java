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

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.Request;
import com.ning.http.client.Response;
import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Signer;
import net.adamcin.httpsig.http.HttpServerTestBody;
import net.adamcin.httpsig.ssh.jce.SSHKey;
import net.adamcin.httpsig.ssh.jce.KeyFormat;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class AsyncUtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AsyncUtilTest.class);

    private static final String TEST_URL = "/index.html?path=/may/get/url/encoded&foo=bar";
    private static final AsyncCompletionHandler<Boolean> DEFAULT_HANDLER = new AsyncCompletionHandler<Boolean>() {
        @Override
        public Boolean onCompleted(Response response) throws Exception {
            return response.getStatusCode() == 200;
        }
    };

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
                        provider.add(new SSHKey(KeyFormat.SSH_RSA, keyPair));


                        AsyncHttpClient client = new AsyncHttpClient();

                        Signer signer = new Signer(provider, getKeyIdentifier());
                        Boolean response = AsyncUtil.login(
                                client, signer,
                                client.prepareGet(getAbsoluteUrl(TEST_URL)).build(),
                                DEFAULT_HANDLER
                        ).get();

                        assertTrue("login should be successful", response);
                    }
                }
        );
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

                DefaultKeychain keychain = new DefaultKeychain();
                keychain.add(new SSHKey(KeyFormat.SSH_RSA, keyPair));

                Signer signer = new Signer(keychain, getKeyIdentifier());
                AsyncHttpClient client = new AsyncHttpClient();

                Boolean badResponse = AsyncUtil.login(
                        client, signer,
                        client.prepareGet(getAbsoluteUrl(TEST_URL)).build(),
                        DEFAULT_HANDLER
                ).get();

                assertFalse("login should not be successful", badResponse);

                Request goodRequestNoLogin = client.prepareGet(getAbsoluteUrl(TEST_URL)).addHeader("x-test", "foo").build();
                Boolean notLoggedIn = client.executeRequest(goodRequestNoLogin, DEFAULT_HANDLER).get();
                assertFalse("bad subsequent request is not successful", notLoggedIn);

                signer.rotateKeys();

                Boolean goodResponse = AsyncUtil.login(
                        client, signer,
                        client.prepareGet(getAbsoluteUrl(TEST_URL))
                                .addHeader("x-test", "foo").build(),
                        DEFAULT_HANDLER
                ).get();

                assertTrue("login should be successful", goodResponse);

                Request goodRequestAfterLogin = client.prepareGet(getAbsoluteUrl(TEST_URL)).addHeader("x-test", "foo").build();
                Boolean loggedIn = client.executeRequest(goodRequestAfterLogin, DEFAULT_HANDLER).get();

                assertTrue("good subsequent request is successful", loggedIn);
            }
        });
    }
}
