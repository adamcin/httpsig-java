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

package net.adamcin.httpsig.ssh.bc;

import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.ssh.jce.FingerprintableKey;
import net.adamcin.httpsig.ssh.jce.KeyFormat;
import net.adamcin.httpsig.ssh.jce.SSHKey;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 */
public class PEMUtilTest {

    @Test
    public void testReadKey() {
        KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("b2048", "id_rsa");
        SSHKey sshKey = new SSHKey(KeyFormat.SSH_RSA, keyPair);

        try {
            Key bcKey = PEMUtil.readKey(KeyTestUtil.getPrivateKeyAsFile("b2048", "id_rsa"), null);

            assertEquals("fingerprints should match", sshKey.getFingerprint(), ((FingerprintableKey) bcKey).getFingerprint());
        } catch (IOException e) {
            FailUtil.sprintFail(e);
        }
    }

    @Test
    public void testEncryptedKey() {
        KeyPair keyPair = KeyTestUtil.getKeyPairFromProperties("withpass", "id_rsa");
        SSHKey sshKey = new SSHKey(KeyFormat.SSH_RSA, keyPair);

        try {
            Key bcKey = PEMUtil.readKey(KeyTestUtil.getPrivateKeyAsFile("withpass", "id_rsa"), "dummydummy".toCharArray());

            assertEquals("fingerprints should match", sshKey.getFingerprint(), ((FingerprintableKey) bcKey).getFingerprint());
        } catch (IOException e) {
            FailUtil.sprintFail(e);
        }
    }
}
