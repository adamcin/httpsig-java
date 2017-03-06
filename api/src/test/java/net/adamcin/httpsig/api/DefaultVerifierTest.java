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

package net.adamcin.httpsig.api;


import net.adamcin.commons.testing.junit.TestBody;
import org.junit.Test;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class DefaultVerifierTest {

    @Test
    public void testVerify() {
        TestBody.test(new TestBody() {
            @Override protected void execute() throws Exception {
                String fingerprint = "fingerprint";

                Keychain identities = new MockKeychain(fingerprint);
                DefaultVerifier v = new DefaultVerifier(identities);
                RequestContent requestContent = new RequestContent.Builder().addDateNow().build();
                Challenge c = new Challenge(DefaultVerifierTest.class.getName(), Constants.DEFAULT_HEADERS, Arrays.asList( Algorithm.SSH_RSA ));

                byte[] content = requestContent.getContent(Constants.DEFAULT_HEADERS, Constants.CHARSET);
                Authorization a = new Authorization(fingerprint, MockKey.mockSignBase64(content), Constants.DEFAULT_HEADERS, Algorithm.SSH_RSA);

                assertTrue("default verifier should verify mock signature ", v.verify(c, requestContent, a));
            }
        });
    }


    @Test
    public void testStrictVerify() {
        TestBody.test(new TestBody() {
            @Override protected void execute() throws Exception {
                String fingerprint = "fingerprint";

                Keychain identities = new MockKeychain(fingerprint);
                DefaultVerifier v = new DefaultVerifier(identities);
                DefaultVerifier strictV = new DefaultVerifier(identities, true);
                RequestContent requestContent = new RequestContent.Builder().setRequestTarget("get", "index.html").addDateNow().build();
                List<String> headers = Arrays.asList(Constants.HEADER_REQUEST_TARGET, Constants.HEADER_DATE);
                Challenge c = new Challenge(DefaultVerifierTest.class.getName(),
                        headers,
                        Arrays.asList( Algorithm.SSH_RSA ));

                byte[] content = requestContent.getContent(headers, Constants.CHARSET);
                byte[] strictContent = requestContent.getBytesToSign(headers, Constants.CHARSET);
                Authorization authz = new Authorization(fingerprint, MockKey.mockSignBase64(content), headers, Algorithm.SSH_RSA);
                Authorization strictAuthz = new Authorization(fingerprint, MockKey.mockSignBase64(strictContent), headers, Algorithm.SSH_RSA);

                assertTrue("default verifier should verify default mock signature ", v.verify(c, requestContent, authz));
                assertTrue("default verifier should verify strict mock signature ", v.verify(c, requestContent, strictAuthz));
                assertTrue("strict verifier should verify strict mock signature ", strictV.verify(c, requestContent, strictAuthz));
                assertFalse("strict verifier should not verify default mock signature ", strictV.verify(c, requestContent, authz));
            }
        });
    }


}
