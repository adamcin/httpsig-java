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

package net.adamcin.httpsig.jce;

import com.jcraft.jsch.HASH;
import com.jcraft.jsch.jce.MD5;
import net.adamcin.commons.testing.junit.FailUtil;
import net.adamcin.httpsig.api.Base64;
import net.adamcin.httpsig.testutil.KeyTestUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.util.List;

import static org.junit.Assert.*;

public class KeyFormatTest {

    @Test
    public void testFingerprint() {
        KeyPair rsaKeyPair = KeyTestUtil.getKeyPairFromProperties("b1024", "id_rsa");

        File rsaPubKeyFile = KeyTestUtil.getPublicKeyAsFile("b1024", "id_rsa");

        try {
            List<AuthorizedKeys.AuthorizedKey> authorizedKeys = AuthorizedKeys.parseAuthorizedKeys(rsaPubKeyFile);
            assertEquals("rsaPubKeyFile should only contain one pubkey", 1, authorizedKeys.size());

            AuthorizedKeys.AuthorizedKey authorizedKey = authorizedKeys.get(0);
            byte[] keyBlob = Base64.fromBase64String(authorizedKey.getEncodedKey());

            Assert.assertEquals(
                    "KeyFormat.SSH_RSA.getFingerprint() should return same output as JSch fingerprint algorithm",
                    getJschFingerprint(keyBlob), KeyFormat.SSH_RSA.getFingerprint(rsaKeyPair.getPublic())
            );
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }

        KeyPair dsaKeyPair = KeyTestUtil.getKeyPairFromProperties("b1024", "id_dsa");

        File dsaPubKeyFile = KeyTestUtil.getPublicKeyAsFile("b1024", "id_dsa");

        try {
            List<AuthorizedKeys.AuthorizedKey> authorizedKeys = AuthorizedKeys.parseAuthorizedKeys(dsaPubKeyFile);
            assertEquals("dsaPubKeyFile should only contain one pubkey", 1, authorizedKeys.size());

            AuthorizedKeys.AuthorizedKey authorizedKey = authorizedKeys.get(0);
            byte[] keyBlob = Base64.fromBase64String(authorizedKey.getEncodedKey());

            assertEquals("KeyFormat.SSH_DSS.getFingerprint() should return same output as JSch fingerprint algorithm",
                         getJschFingerprint(keyBlob), KeyFormat.SSH_DSS.getFingerprint(dsaKeyPair.getPublic()));
        } catch (Exception e) {
            FailUtil.sprintFail(e);
        }

    }

    public static String getJschFingerprint(byte[] keyBlob) throws Exception {
        final String[] fingerPrintChars = {
                "0","1","2","3","4","5","6","7","8","9", "a","b","c","d","e","f"
        };
        HASH hash = new MD5();
        hash.init();
        hash.update(keyBlob, 0, keyBlob.length);
        byte[] foo = hash.digest();
        StringBuffer sb = new StringBuffer();
        int bar;
        for(int i = 0; i < foo.length; i++){
            bar = foo[i]&0xff;
            sb.append(fingerPrintChars[(bar>>>4)&0xf]);
            sb.append(fingerPrintChars[(bar)&0xf]);
            if(i + 1 < foo.length) {
                sb.append(":");
            }
        }
        return sb.toString();
    }
}
