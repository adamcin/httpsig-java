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

import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.sshjce.SSHKey;
import net.adamcin.httpsig.sshjce.KeyFormat;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Logger;

public class PEMHelper {
    private static final Logger LOGGER = Logger.getLogger(PEMHelper.class.getName());

    /**
     * Read a single PEM-formatted key
     * @param is
     * @param passphrase
     * @return
     * @throws IOException
     */
    public static Key readKey(InputStream is, final char[] passphrase) throws IOException {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PEMParser parser = null;
        KeyPair keyPair = null;

        try {
            parser = new PEMParser(new InputStreamReader(is));

            Object o = parser.readObject();
            if (o instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair _encPair = (PEMEncryptedKeyPair) o;
                PEMDecryptorProvider decryptionProv = new JcePEMDecryptorProviderBuilder().build(passphrase);
                keyPair = converter.getKeyPair(_encPair.decryptKeyPair(decryptionProv));
            } else if (o instanceof PEMKeyPair) {
                keyPair = converter.getKeyPair((PEMKeyPair) o);
            }

            if (keyPair != null) {
                if (keyPair.getPrivate() instanceof RSAPrivateKey
                        || keyPair.getPublic() instanceof RSAPublicKey) {
                    return new SSHKey(KeyFormat.SSH_RSA, keyPair);
                } else if (keyPair.getPrivate() instanceof DSAPrivateKey
                        || keyPair.getPublic() instanceof DSAPublicKey) {
                    return new SSHKey(KeyFormat.SSH_DSS, keyPair);
                }
            }

            return null;

        } finally {
            if (parser != null) {
                try { parser.close(); } catch (IOException ignored) {}
            }
        }
    }

    /**
     *
     * Read a single PEM-formatted key
     * @param privateKeyFile
     * @param passphrase
     * @return
     * @throws IOException
     */
    public static Key readKey(File privateKeyFile, final char[] passphrase) throws IOException {
        InputStream is = null;

        try {
            is = new FileInputStream(privateKeyFile);
            return readKey(is, passphrase);
        } finally {
            if (is != null) {
                try { is.close(); } catch (IOException ignored) {}
            }
        }
    }

    /**
     *
     * Read a single PEM-formatted key
     * @param keyBytes
     * @param passphrase
     * @return
     * @throws IOException
     */
    public static Key readKey(byte[] keyBytes, final char[] passphrase) throws IOException {
        ByteArrayInputStream is = null;

        try {
            is = new ByteArrayInputStream(keyBytes);
            return readKey(is, passphrase);
        } finally {
            if (is != null) {
                try { is.close(); } catch (IOException ignored) {}
            }
        }
    }
}
