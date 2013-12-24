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

package net.adamcin.httpsig.ssh.jce;

import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Base64;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Signer;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.ssh.jce.AuthorizedKeys.AuthorizedKey;
import net.adamcin.httpsig.ssh.jce.AuthorizedKeys.PublicPair;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class AuthorizedKeysTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizedKeysTest.class);

    private static final String TEST_AUTHORIZED_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC+Fz0pqK+XoCcukPhnPD+M1zb+FImbh5Lu3pkfW5DM67B6Hr9Q28LuWgNTfLqUn9o01W0TYzXDxtKG9psGuQ0wFJmqYJNbP6eRB3gimcr+C/eyy7N/evs8E36iMi7Si1piPd7QJ5l3D/tThI5cAACHYN0uqwphpXt4Lw2OZxIAQw== dummy@nowhere";

    @Test
    public void testParseAuthorizedKey() {

        try {
            AuthorizedKeys.AuthorizedKey authorizedKey = AuthorizedKeys.parseAuthorizedKey(TEST_AUTHORIZED_KEY);
            assertNotNull("authorizedKey should not be null", authorizedKey);
            assertEquals("authorizedKey format should be", "ssh-rsa", authorizedKey.getFormat());
            assertEquals(
                    "authorizedKey encodedKey should be",
                    "AAAAB3NzaC1yc2EAAAADAQABAAAAgQC+Fz0pqK+XoCcukPhnPD+M1zb+FImbh5Lu3pkfW5DM67B6Hr9Q28LuWgNTfLqUn9o01W0TYzXDxtKG9psGuQ0wFJmqYJNbP6eRB3gimcr+C/eyy7N/evs8E36iMi7Si1piPd7QJ5l3D/tThI5cAACHYN0uqwphpXt4Lw2OZxIAQw==",
                    authorizedKey.getEncodedKey()
            );
            assertEquals("authorizedKey comment should be", "dummy@nowhere", authorizedKey.getComment());

            File rsaPubKeyFile = KeyTestUtil.getPublicKeyAsFile("b1024", "id_rsa");
            List<AuthorizedKeys.AuthorizedKey> authorizedKeys = AuthorizedKeys.parseAuthorizedKeys(rsaPubKeyFile);
            assertEquals("rsaPubKeyFile should only contain one pubkey", 1, authorizedKeys.size());
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }
    }

    @Test
    public void testAuthorizedKeysVerifier() {
        compareAuthorizedKeyToKeyPair("b1024", "id_dsa", KeyFormat.SSH_DSS);
        compareAuthorizedKeyToKeyPair("b1024", "id_rsa", KeyFormat.SSH_RSA);
        compareAuthorizedKeyToKeyPair("b2048", "id_rsa", KeyFormat.SSH_RSA);
        compareAuthorizedKeyToKeyPair("b4096", "id_rsa", KeyFormat.SSH_RSA);
        compareAuthorizedKeyToKeyPair("withpass", "id_dsa", KeyFormat.SSH_DSS);
        compareAuthorizedKeyToKeyPair("withpass", "id_rsa", KeyFormat.SSH_RSA);
    }

    public void compareAuthorizedKeyToKeyPair(String parentName, String keyName, KeyFormat format) {
        final String id = "[" + parentName + "/" + keyName + "] ";
        LOGGER.info("[compareAuthorizedKeyToKeyPair {}] begin", id);

        try {
            List<AuthorizedKey> keys = AuthorizedKeys.parseAuthorizedKeys(
                    KeyTestUtil.getPublicKeyAsFile(parentName, keyName)
            );

            AuthorizedKey key = keys.get(0);

            PublicPair publicPair = AuthorizedKeys.readPublicPair(Base64.fromBase64String(key.getEncodedKey()));

            assertEquals(id + "public pair should be KeyFormat", format, publicPair.getFormat());

            KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties(parentName, keyName);

            if (format == KeyFormat.SSH_RSA) {
                assertTrue(
                        id + "keyPair.getPublic() should be instance of RSAPublicKey",
                        keyPair.getPublic() instanceof RSAPublicKey
                );
                assertTrue(
                        "publicPair.getSpec() should be instance of RSAPublicKeySpec",
                        publicPair.getSpec() instanceof RSAPublicKeySpec
                );

                RSAPublicKeySpec publicPairSpec = (RSAPublicKeySpec) publicPair.getSpec();
                RSAPublicKeySpec keyPairSpec = format.getKeyFactory().getKeySpec(
                        keyPair.getPublic(), RSAPublicKeySpec.class
                );

                assertEquals(
                        "public exponents should match", keyPairSpec.getPublicExponent(),
                        publicPairSpec.getPublicExponent()
                );
                assertEquals("moduli should match", keyPairSpec.getModulus(), publicPairSpec.getModulus());
            } else if (format == KeyFormat.SSH_DSS) {
                assertTrue(
                        id + "keyPair.getPublic() should be instance of DSAPublicKey",
                        keyPair.getPublic() instanceof DSAPublicKey
                );
                assertTrue(
                        id + "publicPair.getSpec() should be instance of DSAPublicKeySpec",
                        publicPair.getSpec() instanceof DSAPublicKeySpec
                );

                DSAPublicKeySpec publicPairSpec = (DSAPublicKeySpec) publicPair.getSpec();
                DSAPublicKeySpec keyPairSpec = format.getKeyFactory().getKeySpec(
                        keyPair.getPublic(), DSAPublicKeySpec.class
                );

                assertEquals(id + "G should match", keyPairSpec.getG(), publicPairSpec.getG());
                assertEquals(id + "P should match", keyPairSpec.getP(), publicPairSpec.getP());
                assertEquals(id + "Q should match", keyPairSpec.getQ(), publicPairSpec.getQ());
                assertEquals(id + "Y should match", keyPairSpec.getY(), publicPairSpec.getY());
            } else {
                throw new IllegalArgumentException("unknown key format");
            }

            Key jceKey = new SSHKey(format, keyPair);
            Key akKey = AuthorizedKeys.createPublicIdentity(publicPair);

            assertEquals(id + "fingerprints should match", jceKey.getId(), akKey.getId());

            DefaultKeychain signingAndVerifying = new DefaultKeychain(Arrays.asList(jceKey));
            DefaultKeychain verifying = new DefaultKeychain(Arrays.asList(akKey));

            Signer signer = new Signer(signingAndVerifying);
            Verifier sameKeyVerifier = new Verifier(signingAndVerifying);
            Verifier publicKeyVerifier = new Verifier(verifying);
            SignatureBuilder signatureBuilder = new SignatureBuilder();
            signatureBuilder.addDateNow();

            final String realm = getClass().getName();

            LOGGER.info("[compareAuthorizedKeyToKeyPair {}] before challenge", id);
            Challenge challenge = new Challenge(realm, Constants.DEFAULT_HEADERS, format.getSignatureAlgorithms());
            signer.rotateKeys(challenge, null);

            LOGGER.info("[compareAuthorizedKeyToKeyPair {}] before authorization", id);
            Authorization authorization = signer.sign(signatureBuilder);

            LOGGER.info("[compareAuthorizedKeyToKeyPair {}] before verification", id);
            assertTrue(id + "same key verifier should verify", sameKeyVerifier.verify(challenge, signatureBuilder, authorization));
            assertTrue(id + "public key verifier should verify", publicKeyVerifier.verify(challenge, signatureBuilder, authorization));

        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }
    }
}
