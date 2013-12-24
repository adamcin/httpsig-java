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

import java.util.Arrays;

import static org.junit.Assert.*;

public class VerifierTest {

    @Test
    public void testVerify() {
        TestBody.test(new TestBody() {
            @Override protected void execute() throws Exception {
                String fingerprint = "fingerprint";

                Keychain identities = new MockKeychain(fingerprint);
                Verifier v = new Verifier(identities);
                RequestContent requestContent = new RequestContent.Builder().addDateNow().build();
                Challenge c = new Challenge(VerifierTest.class.getName(), Constants.DEFAULT_HEADERS, Arrays.asList( Algorithm.SSH_RSA ));

                byte[] content = requestContent.getContent(Constants.DEFAULT_HEADERS, Constants.CHARSET);
                Authorization a = new Authorization(fingerprint, MockKey.mockSignBase64(content), Constants.DEFAULT_HEADERS, Algorithm.SSH_RSA);

                assertTrue("default verifier should verify mock signature ", v.verify(c, requestContent, a));
            }
        });
    }


}
