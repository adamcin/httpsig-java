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

package net.adamcin.httpsig.testutil;

import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.httpsig.api.Base64;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;

import static org.junit.Assert.*;

public class KeyTestUtilTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyTestUtilTest.class);

    @Test
    public void testGetAuthorizedKeys() {
        File authorizedKeysFile = KeyTestUtil.getAuthorizedKeysFile();
        assertNotNull("authorizedKeysFile should not be null", authorizedKeysFile);
        assertTrue("authorizedKeysFile should be readable", authorizedKeysFile.canRead());
    }

    @Test
    public void testGetPublicKeyAsFile() {
        File b1024_dsa = KeyTestUtil.getPublicKeyAsFile("b1024", "id_dsa");
        assertNotNull("b1024_dsa should not be null", b1024_dsa);
        assertTrue("b1024_dsa should be readable", b1024_dsa.canRead());

        File b1024_rsa = KeyTestUtil.getPublicKeyAsFile("b1024", "id_rsa");
        assertNotNull("b1024_rsa should not be null", b1024_rsa);
        assertTrue("b1024_rsa should be readable", b1024_rsa.canRead());

        File b2048_rsa = KeyTestUtil.getPublicKeyAsFile("b2048", "id_rsa");
        assertNotNull("b2048_rsa should not be null", b2048_rsa);
        assertTrue("b2048_rsa should be readable", b2048_rsa.canRead());

        File b4096_rsa = KeyTestUtil.getPublicKeyAsFile("b4096", "id_rsa");
        assertNotNull("b4096_rsa should not be null", b4096_rsa);
        assertTrue("b4096_rsa should be readable", b4096_rsa.canRead());

        File withpass_dsa = KeyTestUtil.getPublicKeyAsFile("withpass", "id_dsa");
        assertNotNull("withpass_dsa should not be null", withpass_dsa);
        assertTrue("withpass_dsa should be readable", withpass_dsa.canRead());

        File withpass_rsa = KeyTestUtil.getPublicKeyAsFile("withpass", "id_rsa");
        assertNotNull("withpass_rsa should not be null", withpass_rsa);
        assertTrue("withpass_rsa should be readable", withpass_rsa.canRead());
    }

    @Test
    public void testGetPrivateKeyAsFile() {
        File b1024_dsa = KeyTestUtil.getPrivateKeyAsFile("b1024", "id_dsa");
        assertNotNull("b1024_dsa should not be null", b1024_dsa);
        assertTrue("b1024_dsa should be readable", b1024_dsa.canRead());

        File b1024_rsa = KeyTestUtil.getPrivateKeyAsFile("b1024", "id_rsa");
        assertNotNull("b1024_rsa should not be null", b1024_rsa);
        assertTrue("b1024_rsa should be readable", b1024_rsa.canRead());

        File b2048_rsa = KeyTestUtil.getPrivateKeyAsFile("b2048", "id_rsa");
        assertNotNull("b2048_rsa should not be null", b2048_rsa);
        assertTrue("b2048_rsa should be readable", b2048_rsa.canRead());

        File b4096_rsa = KeyTestUtil.getPrivateKeyAsFile("b4096", "id_rsa");
        assertNotNull("b4096_rsa should not be null", b4096_rsa);
        assertTrue("b4096_rsa should be readable", b4096_rsa.canRead());

        File withpass_dsa = KeyTestUtil.getPrivateKeyAsFile("withpass", "id_dsa");
        assertNotNull("withpass_dsa should not be null", withpass_dsa);
        assertTrue("withpass_dsa should be readable", withpass_dsa.canRead());

        File withpass_rsa = KeyTestUtil.getPrivateKeyAsFile("withpass", "id_rsa");
        assertNotNull("withpass_rsa should not be null", withpass_rsa);
        assertTrue("withpass_rsa should be readable", withpass_rsa.canRead());
    }


    @Test
    public void testGetPrivateKeyAsKeyPair() {
        KeyPair b1024_dsa = KeyTestUtil.getPrivateKeyAsKeyPair("b1024", "id_dsa", null);
        assertNotNull("b1024_dsa should not be null", b1024_dsa);
        assertTrue("b1024_dsa should have a DSAPublicKey", b1024_dsa.getPublic() instanceof DSAPublicKey);
        assertTrue("b1024_dsa should have a DSAPrivateKey", b1024_dsa.getPrivate() instanceof DSAPrivateKey);

        KeyPair b1024_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("b1024", "id_rsa", null);
        assertNotNull("b1024_rsa should not be null", b1024_rsa);
        assertTrue("b1024_rsa should have a RSAPublicKey", b1024_rsa.getPublic() instanceof RSAPublicKey);
        assertTrue("b1024_rsa should have a RSAPrivateKey", b1024_rsa.getPrivate() instanceof RSAPrivateKey);

        KeyPair b2048_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("b2048", "id_rsa", null);
        assertNotNull("b2048_rsa should not be null", b2048_rsa);
        assertTrue("b2048_rsa should have a RSAPublicKey", b2048_rsa.getPublic() instanceof RSAPublicKey);
        assertTrue("b2048_rsa should have a RSAPrivateKey", b2048_rsa.getPrivate() instanceof RSAPrivateKey);

        KeyPair b4096_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("b4096", "id_rsa", null);
        assertNotNull("b4096_rsa should not be null", b4096_rsa);
        assertTrue("b4096_rsa should have a RSAPublicKey", b4096_rsa.getPublic() instanceof RSAPublicKey);
        assertTrue("b4096_rsa should have a RSAPrivateKey", b4096_rsa.getPrivate() instanceof RSAPrivateKey);

        KeyPair withpass_dsa = KeyTestUtil.getPrivateKeyAsKeyPair("withpass", "id_dsa", "dummydummy");
        assertNotNull("withpass_dsa should not be null", withpass_dsa);
        assertTrue("withpass_dsa should have a DSAPublicKey", withpass_dsa.getPublic() instanceof DSAPublicKey);
        assertTrue("withpass_dsa should have a DSAPrivateKey", withpass_dsa.getPrivate() instanceof DSAPrivateKey);

        KeyPair withpass_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("withpass", "id_rsa", "dummydummy");
        assertNotNull("withpass_rsa should not be null", withpass_rsa);
        assertTrue("withpass_rsa should have a RSAPublicKey", withpass_rsa.getPublic() instanceof RSAPublicKey);
        assertTrue("withpass_rsa should have a RSAPrivateKey", withpass_rsa.getPrivate() instanceof RSAPrivateKey);
    }

    @Test
    public void testGetKeyPairFromProperties() {
        KeyPair props_b1024_dsa = KeyTestUtil.getKeyPairFromProperties("b1024", "id_dsa");
        KeyPair id_b1024_dsa = KeyTestUtil.getPrivateKeyAsKeyPair("b1024", "id_dsa", null);
        assertEquals("props_b1024_dsa public equals id_b1024_dsa public", id_b1024_dsa.getPublic(), props_b1024_dsa.getPublic());
        assertEquals(
                "props_b1024_dsa private equals id_b1024_dsa private", id_b1024_dsa.getPrivate(),
                props_b1024_dsa.getPrivate()
        );

        KeyPair props_b1024_rsa = KeyTestUtil.getKeyPairFromProperties("b1024", "id_rsa");
        KeyPair id_b1024_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("b1024", "id_rsa", null);
        assertEquals("props_b1024_rsa public equals id_b1024_rsa public", id_b1024_rsa.getPublic(), props_b1024_rsa.getPublic());
        assertEquals(
                "props_b1024_rsa private equals id_b1024_rsa private", id_b1024_rsa.getPrivate(),
                props_b1024_rsa.getPrivate()
        );

        KeyPair props_b2048_rsa = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");
        KeyPair id_b2048_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("b2048", "id_rsa", null);
        assertEquals("props_b2048_rsa public equals id_b2048_rsa public", id_b2048_rsa.getPublic(), props_b2048_rsa.getPublic());
        assertEquals("props_b2048_rsa private equals id_b2048_rsa private", id_b2048_rsa.getPrivate(), props_b2048_rsa.getPrivate());

        KeyPair props_b4096_rsa = KeyTestUtil.getKeyPairFromProperties("b4096", "id_rsa");
        KeyPair id_b4096_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("b4096", "id_rsa", null);
        assertEquals("props_b4096_rsa public equals id_b4096_rsa public", id_b4096_rsa.getPublic(), props_b4096_rsa.getPublic());
        assertEquals("props_b4096_rsa private equals id_b4096_rsa private", id_b4096_rsa.getPrivate(), props_b4096_rsa.getPrivate());

        KeyPair props_withpass_dsa = KeyTestUtil.getKeyPairFromProperties("withpass", "id_dsa");
        KeyPair id_withpass_dsa = KeyTestUtil.getPrivateKeyAsKeyPair("withpass", "id_dsa", "dummydummy");
        assertEquals("props_withpass_dsa public equals id_withpass_dsa public", id_withpass_dsa.getPublic(), props_withpass_dsa.getPublic());
        assertEquals("props_withpass_dsa private equals id_withpass_dsa private", id_withpass_dsa.getPrivate(), props_withpass_dsa.getPrivate());

        KeyPair props_withpass_rsa = KeyTestUtil.getKeyPairFromProperties("withpass", "id_rsa");
        KeyPair id_withpass_rsa = KeyTestUtil.getPrivateKeyAsKeyPair("withpass", "id_rsa", "dummydummy");
        assertEquals("props_withpass_rsa public equals id_withpass_rsa public", id_withpass_rsa.getPublic(), props_withpass_rsa.getPublic());
        assertEquals("props_withpass_rsa private equals id_withpass_rsa private", id_withpass_rsa.getPrivate(), props_withpass_rsa.getPrivate());
    }

    @Test
    public void testPublicKeysMatchAuthorizedKeys() {
        testPublicKeyMatchesAuthorizedKey("b1024", "id_dsa");
        testPublicKeyMatchesAuthorizedKey("b1024", "id_rsa");
        testPublicKeyMatchesAuthorizedKey("b2048", "id_rsa");
        testPublicKeyMatchesAuthorizedKey("b4096", "id_rsa");
        testPublicKeyMatchesAuthorizedKey("withpass", "id_dsa");
        testPublicKeyMatchesAuthorizedKey("withpass", "id_rsa");
    }

    private void testPublicKeyMatchesAuthorizedKey(String parentName, String keyName) {
        String realEncoded = Base64.toBase64String(
                KeyTestUtil.dumpKeyBlob(KeyTestUtil.getKeyPairFromProperties(parentName, keyName).getPublic())
        );

        Scanner pubScanner = null;
        try {
            pubScanner = new Scanner(KeyTestUtil.getPublicKeyAsFile(parentName, keyName));
            assertTrue(".pub file should have at least one line", pubScanner.hasNextLine());

            String authorizedKeyBlob = pubScanner.nextLine().split("\\s+")[1];
            assertTrue("[keyPair.getPublic() <-> *.pub] " + parentName + "/" + keyName, realEncoded.equals(authorizedKeyBlob));
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        } finally {
            if (pubScanner != null) {
                pubScanner.close();
            }
        }

        Scanner authKeysScanner = null;
        try {
            authKeysScanner = new Scanner(KeyTestUtil.getAuthorizedKeysStream());

            boolean foundKey = false;

            while (authKeysScanner.hasNextLine()) {
                String authKeyBlob = authKeysScanner.nextLine().split("\\s+")[1];
                if (realEncoded.equals(authKeyBlob)) {
                    foundKey = true;
                    break;
                }
            }

            assertTrue("found public key blob in authorized_keys", foundKey);
        } catch (Exception e) {
            if (authKeysScanner != null) {
                authKeysScanner.close();
            }
        }
    }
}
