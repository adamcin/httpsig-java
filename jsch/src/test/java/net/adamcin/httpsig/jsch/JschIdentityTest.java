package net.adamcin.httpsig.jsch;

import com.jcraft.jsch.JSch;
import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.Signer;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.httpsig.jce.JCEKey;
import net.adamcin.httpsig.jce.KeyFormat;
import net.adamcin.httpsig.api.DefaultKeychain;
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

        String nonce = "sessionId";
        ChallengeBuilder challenge = new ChallengeBuilder("myRealm", nonce, "localhost", "test");

        Reader reader = null;
        try {
            roundTrip(challenge, KeyFormat.SSH_RSA, "b1024", "id_rsa", null);
            roundTrip(challenge, KeyFormat.SSH_DSS, "b1024", "id_dsa", null);
            roundTrip(challenge, KeyFormat.SSH_RSA, "b2048", "id_rsa", null);
            roundTrip(challenge, KeyFormat.SSH_RSA, "b4096", "id_rsa", null);
            roundTrip(challenge, KeyFormat.SSH_DSS, "withpass", "id_dsa", "dummydummy");
            roundTrip(challenge, KeyFormat.SSH_RSA, "withpass", "id_rsa", "dummydummy");
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }

    public void roundTrip(ChallengeBuilder challengeBuilder, KeyFormat format, String parentName, String keyName, String passphrase)
            throws Exception {

        final String id = "[" + parentName + "/" + keyName + "] ";

        Verifier dverifier = AuthorizedKeys.newVerifier(KeyTestUtil.getPublicKeyAsFile(parentName, keyName));
        String fingerprint = dverifier.getKeychain().fingerprints().iterator().next();

        Challenge challenge = challengeBuilder.build(fingerprint, format.getSignatureAlgorithms());

        JSch jSchSigner = new JSch();

        jSchSigner.addIdentity(KeyTestUtil.getPrivateKeyAsFile(parentName, keyName).getAbsolutePath(), passphrase);

        Keychain sprovider = JschKey.getIdentities(jSchSigner);

        assertEquals(id + "sprovider should contain only one identity", 1, sprovider.fingerprints().size());
        assertEquals(id + "fingerprints should match", fingerprint, sprovider.fingerprints().iterator().next());

        Signer jsigner = new Signer(sprovider);
        Verifier jverifier = new Verifier(sprovider);

        Signer dsigner = new Signer(new DefaultKeychain(
                        Arrays.asList(new JCEKey(format, KeyTestUtil.getKeyPairFromProperties(parentName, keyName)))));

        Authorization jpacket = jsigner.sign(challenge);
        Authorization dpacket = dsigner.sign(challenge);

        LOGGER.info(id + "jpacket={}, dpacket={}", KeyTestUtil.bytesToHex(jpacket.getSignatureBytes()),
                    KeyTestUtil.bytesToHex(dpacket.getSignatureBytes()));

        assertEquals(id + "jce fingerprints should match", fingerprint, dsigner.getFingerprints().iterator().next());
        assertTrue(id + "round trip using jce identities", dverifier.verify(challenge, dpacket));
        assertTrue(id + "round trip using JschIdentities", jverifier.verify(challenge, jpacket));

        assertTrue(id + "round trip using jverifier + dsigner", jverifier.verify(challenge, dpacket));
        assertTrue(id + "round trip using dverifier + jsigner", dverifier.verify(challenge, jpacket));
    }

}
