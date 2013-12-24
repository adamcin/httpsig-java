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

package net.adamcin.httpsig.helpers.http4;

import net.adamcin.commons.testing.junit.TestBody;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.helpers.HttpServerTestBody;
import net.adamcin.httpsig.jce.SSHKey;
import net.adamcin.httpsig.jce.KeyFormat;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.DefaultHttpClient;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class Http4UtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(Http4UtilTest.class);

    private static final String TEST_URL = "/index.html?path=/may/get/url/encoded&foo=bar";

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

                DefaultHttpClient client = new DefaultHttpClient();

                Http4Util.enableAuth(client, provider, getKeyIdentifier());
                HttpUriRequest request = new HttpGet(getAbsoluteUrl(TEST_URL));
                HttpResponse response = client.execute(request);

                assertEquals("should return 200", 200, response.getStatusLine().getStatusCode());

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
                provider.add(new SSHKey(KeyFormat.SSH_RSA, keyPair));

                DefaultHttpClient client = new DefaultHttpClient();

                Http4Util.enableAuth(client, provider, getKeyIdentifier());

                HttpUriRequest badRequest = new HttpGet(getAbsoluteUrl(TEST_URL));
                HttpResponse badResponse = client.execute(badRequest);

                badResponse.getEntity().writeTo(new NullOutputStream());

                assertEquals("should return 401", 401, badResponse.getStatusLine().getStatusCode());

                HttpUriRequest goodRequest = new HttpGet(getAbsoluteUrl(TEST_URL));
                goodRequest.addHeader("x-test", "foo");
                HttpResponse goodResponse = client.execute(goodRequest);

                goodResponse.getEntity().writeTo(new NullOutputStream());
                assertEquals("should return 200", 200, goodResponse.getStatusLine().getStatusCode());
            }
        });
    }
}
