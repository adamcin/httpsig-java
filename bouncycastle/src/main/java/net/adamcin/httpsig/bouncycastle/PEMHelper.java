package net.adamcin.httpsig.bouncycastle;

import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.jce.JCEKey;
import net.adamcin.httpsig.jce.KeyFormat;
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
                    return new JCEKey(KeyFormat.SSH_RSA, keyPair);
                } else if (keyPair.getPrivate() instanceof DSAPrivateKey
                        || keyPair.getPublic() instanceof DSAPublicKey) {
                    return new JCEKey(KeyFormat.SSH_DSS, keyPair);
                }
            }

            return null;

        } finally {
            if (parser != null) {
                try { parser.close(); } catch (IOException ignored) {}
            }
        }
    }

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
