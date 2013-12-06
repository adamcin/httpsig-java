package net.adamcin.httpsig.testutil;

import net.adamcin.commons.testing.junit.FailUtil;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Properties;

/**
 *
 */
public class KeyTestUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyTestUtil.class);
    private static final String BOUNCY_CASTLE = "BC";

    public static final String P_TYPE = "type";
    public static final String TYPE_RSA = "ssh-rsa";
    public static final String TYPE_DSA = "ssh-dss";

    public static final String DSA_P = "p";
    public static final String DSA_Q = "q";
    public static final String DSA_G = "g";
    public static final String DSA_Y = "y";
    public static final String DSA_X = "x";

    public static final String RSA_N = "n";
    public static final String RSA_E = "e";
    public static final String RSA_D = "d";
    public static final String RSA_P = "p";
    public static final String RSA_Q = "q";
    public static final String RSA_PE = "pe";
    public static final String RSA_QE = "qe";
    public static final String RSA_U = "u";

    static {
        try {
            if (java.security.Security.getProvider(BOUNCY_CASTLE) == null) {
                LOGGER.info("Trying to register BouncyCastle as a JCE provider");
                java.security.Security.addProvider(new BouncyCastleProvider());
                MessageDigest.getInstance("MD5", BOUNCY_CASTLE);
                KeyAgreement.getInstance("DH", BOUNCY_CASTLE);
                LOGGER.info("Registration succeeded");
            } else {
                LOGGER.info("BouncyCastle already registered ");
            }
        } catch (Exception e) {
            LOGGER.error("Failed to register bouncycastle provider", e);
        }
    }

    private static final File TEST_TEMP = new File("target/test-temp");
    static {
        TEST_TEMP.mkdirs();
        new File(TEST_TEMP, "b1024").mkdirs();
        new File(TEST_TEMP, "b2048").mkdirs();
        new File(TEST_TEMP, "b4096").mkdirs();
        new File(TEST_TEMP, "withpass").mkdirs();
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for ( int j = 0; j < bytes.length; j++ ) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static InputStream getAuthorizedKeysStream() {
        return KeyTestUtil.class.getResourceAsStream("/authorized_keys");
    }

    public static File getAuthorizedKeysFile() {
        return getResourceAsFile("/authorized_keys");
    }

    public static File getPrivateKeyAsFile(String parentName, String keyName) {
        return getResourceAsFile("/" + parentName + "/" + keyName);
    }

    public static byte[] dumpKeyBlob(PublicKey publicKey) {
        ByteArrayOutputStream byteOs = new ByteArrayOutputStream();

        try {
            if (publicKey instanceof RSAPublicKey) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                DataOutputStream dos = new DataOutputStream(byteOs);
                dos.writeInt("ssh-rsa".getBytes().length);
                dos.write("ssh-rsa".getBytes());
                dos.writeInt(rsaPublicKey.getPublicExponent().toByteArray().length);
                dos.write(rsaPublicKey.getPublicExponent().toByteArray());
                dos.writeInt(rsaPublicKey.getModulus().toByteArray().length);
                dos.write(rsaPublicKey.getModulus().toByteArray());
            } else if (publicKey instanceof DSAPublicKey) {
                DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
                DSAParams dsaParams = dsaPublicKey.getParams();

                DataOutputStream dos = new DataOutputStream(byteOs);
                dos.writeInt("ssh-dss".getBytes().length);
                dos.write("ssh-dss".getBytes());
                dos.writeInt(dsaParams.getP().toByteArray().length);
                dos.write(dsaParams.getP().toByteArray());
                dos.writeInt(dsaParams.getQ().toByteArray().length);
                dos.write(dsaParams.getQ().toByteArray());
                dos.writeInt(dsaParams.getG().toByteArray().length);
                dos.write(dsaParams.getG().toByteArray());
                dos.writeInt(dsaPublicKey.getY().toByteArray().length);
                dos.write(dsaPublicKey.getY().toByteArray());
            } else {
                throw new IllegalArgumentException("Not a supported public key: " + publicKey);
            }
        } catch (IOException e) {
            // shouldn't happen
            LOGGER.error("failed to dump public key blob", e);
        }
        return byteOs.toByteArray();
    }

    public static KeyPair getKeyPairFromProperties(String parentName, String keyName) {
        InputStream is = null;
        try {
            is = KeyTestUtil.class.getResourceAsStream("/" + parentName + "/" + keyName + ".properties");
            Properties props = new Properties();
            props.load(is);
            if (TYPE_RSA.equals(props.getProperty(P_TYPE))) {
                RSAPrivateKeySpec privSpec = null;
                if (props.getProperty(RSA_P) != null && props.getProperty(RSA_Q) != null && props.getProperty(RSA_U) != null) {
                    privSpec = new RSAPrivateCrtKeySpec(new BigInteger(props.getProperty(RSA_N)),
                                                        new BigInteger(props.getProperty(RSA_E)),
                                                        new BigInteger(props.getProperty(RSA_D)),
                                                        new BigInteger(props.getProperty(RSA_P)),
                                                        new BigInteger(props.getProperty(RSA_Q)),
                                                        new BigInteger(props.getProperty(RSA_PE)),
                                                        new BigInteger(props.getProperty(RSA_QE)),
                                                        new BigInteger(props.getProperty(RSA_U)));
                } else {
                    privSpec = new RSAPrivateKeySpec(new BigInteger(props.getProperty(RSA_N)),
                                          new BigInteger(props.getProperty(RSA_D)));
                }
                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(new BigInteger(props.getProperty(RSA_N)),
                                                                   new BigInteger(props.getProperty(RSA_E)));

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return new KeyPair(keyFactory.generatePublic(pubSpec), keyFactory.generatePrivate(privSpec));
            } else if (TYPE_DSA.equals(props.getProperty(P_TYPE))) {
                DSAPrivateKeySpec privSpec = new DSAPrivateKeySpec(new BigInteger(props.getProperty(DSA_X)),
                                                                   new BigInteger(props.getProperty(DSA_P)),
                                                                   new BigInteger(props.getProperty(DSA_Q)),
                                                                   new BigInteger(props.getProperty(DSA_G)));
                DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(new BigInteger(props.getProperty(DSA_Y)),
                                                                   new BigInteger(props.getProperty(DSA_P)),
                                                                   new BigInteger(props.getProperty(DSA_Q)),
                                                                   new BigInteger(props.getProperty(DSA_G)));
                KeyFactory keyFactory = KeyFactory.getInstance("DSA");
                return new KeyPair(keyFactory.generatePublic(pubSpec), keyFactory.generatePrivate(privSpec));
            }
        } catch (Exception e) {
            LOGGER.error("Failed to read properties", e);
        } finally {
            IOUtils.closeQuietly(is);
        }

        return null;
    }

    public static KeyPair getPrivateKeyAsKeyPair(String parentName, String keyName, final String passphrase) {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

        File privateKeyFile = getPrivateKeyAsFile(parentName, keyName);
        InputStream is = null;
        PEMParser parser = null;
        try {
            is = new FileInputStream(privateKeyFile);
            parser = new PEMParser(new InputStreamReader(is));

            Object o = parser.readObject();
            if (o instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair _encPair = (PEMEncryptedKeyPair) o;
                PEMDecryptorProvider decryptionProv = new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
                return converter.getKeyPair(_encPair.decryptKeyPair(decryptionProv));
            } else if (o instanceof PEMKeyPair) {
                return converter.getKeyPair((PEMKeyPair) o);
            }
        } catch (Exception e) {
            LOGGER.error("failed to parse private key file: parent=" + parentName + " keyName=" + keyName, e);
        } finally {
            IOUtils.closeQuietly(is);
            IOUtils.closeQuietly(parser);
        }

        return null;
    }

    public static File getPublicKeyAsFile(String parentName, String keyName) {
        return getResourceAsFile("/" + parentName + "/" + keyName + ".pub");
    }

    private static File getResourceAsFile(String name) {
        File temp = new File(TEST_TEMP, name.substring(1));
        if (temp.exists()) {
            return temp;
        }
        InputStream is = null;
        OutputStream os = null;
        try {
            is = KeyTestUtil.class.getResourceAsStream(name);
            os = new FileOutputStream(temp);
            IOUtils.copy(is, os);
            return temp;
        } catch (IOException e) {
            FailUtil.sprintFail(e);
        } finally {
            IOUtils.closeQuietly(is);
            IOUtils.closeQuietly(os);
        }
        return null;
    }
}
