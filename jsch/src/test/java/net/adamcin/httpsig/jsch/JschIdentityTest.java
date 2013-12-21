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

package net.adamcin.httpsig.jsch;

import com.jcraft.jsch.JSch;
import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Signer;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.httpsig.jce.JCEKey;
import net.adamcin.httpsig.jce.KeyFormat;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Reader;
import java.util.Arrays;

import static org.junit.Assert.*;

public class JschIdentityTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(JschIdentityTest.class);

    @Test
    public void testSignature() {

        Reader reader = null;
        try {
            roundTrip(KeyFormat.SSH_RSA, "b1024", "id_rsa", null);
            roundTrip(KeyFormat.SSH_DSS, "b1024", "id_dsa", null);
            roundTrip(KeyFormat.SSH_RSA, "b2048", "id_rsa", null);
            roundTrip(KeyFormat.SSH_RSA, "b4096", "id_rsa", null);
            roundTrip(KeyFormat.SSH_DSS, "withpass", "id_dsa", "dummydummy");
            roundTrip(KeyFormat.SSH_RSA, "withpass", "id_rsa", "dummydummy");
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }

    public void roundTrip(KeyFormat format, String parentName, String keyName, String passphrase)
            throws Exception {

        final String id = "[" + parentName + "/" + keyName + "] ";

        Verifier dverifier = new Verifier(AuthorizedKeys.newKeychain(KeyTestUtil.getPublicKeyAsFile(parentName, keyName)));
        String fingerprint = dverifier.getKeychain().currentKey().getId();

        Challenge challenge = new Challenge("myRealm", Constants.DEFAULT_HEADERS, format.getSignatureAlgorithms());

        JSch jSchSigner = new JSch();

        jSchSigner.addIdentity(KeyTestUtil.getPrivateKeyAsFile(parentName, keyName).getAbsolutePath(), passphrase);

        Keychain sprovider = JschKey.getIdentities(jSchSigner);

        assertEquals(id + "sprovider should contain only one identity", 1, sprovider.toMap(null).size());
        assertEquals(id + "fingerprints should match", fingerprint, sprovider.iterator().next().getId());

        Signer jsigner = new Signer(sprovider);
        Verifier jverifier = new Verifier(sprovider);
        SignatureBuilder signatureBuilder = new SignatureBuilder();
        signatureBuilder.addDateNow();

        Signer dsigner = new Signer(new DefaultKeychain(
                        Arrays.asList(new JCEKey(format, KeyTestUtil.getKeyPairFromProperties(parentName, keyName)))));

        jsigner.rotateKeys(challenge);
        Authorization jpacket = jsigner.sign(signatureBuilder);

        dsigner.rotateKeys(challenge);
        Authorization dpacket = dsigner.sign(signatureBuilder);

        LOGGER.info(id + "jpacket={}, dpacket={}", KeyTestUtil.bytesToHex(jpacket.getSignatureBytes()),
                    KeyTestUtil.bytesToHex(dpacket.getSignatureBytes()));

        assertEquals(id + "jce fingerprints should match", fingerprint, dsigner.getKeychain().currentKey().getId());
        assertTrue(id + "round trip using jce identities", dverifier.verify(challenge, signatureBuilder, dpacket));
        assertTrue(id + "round trip using JschIdentities", jverifier.verify(challenge, signatureBuilder, jpacket));

        assertTrue(id + "round trip using jverifier + dsigner", jverifier.verify(challenge, signatureBuilder, dpacket));
        assertTrue(id + "round trip using dverifier + jsigner", dverifier.verify(challenge, signatureBuilder, jpacket));
    }

}
