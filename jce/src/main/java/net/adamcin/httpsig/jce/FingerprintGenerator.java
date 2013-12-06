package net.adamcin.httpsig.jce;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

public abstract class FingerprintGenerator {
    private static final Logger LOGGER = LoggerFactory.getLogger(FingerprintGenerator.class);

    abstract String getFingerprint(PublicKey publicKey);

    public static final FingerprintGenerator NOP = new FingerprintGenerator() {
        @Override String getFingerprint(PublicKey publicKey) { return ""; }
    };

    public static final FingerprintGenerator DSA = new FingerprintGenerator() {
        public String getFingerprint(PublicKey publicKey) {
            ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
            try {
                if (publicKey instanceof DSAPublicKey) {
                    DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
                    DSAParams dsaParams = dsaPublicKey.getParams();

                    DataOutputStream dos = new DataOutputStream(byteOs);
                    dos.writeInt(KeyFormat.SSH_DSS.getIdentifier().getBytes().length);
                    dos.write(KeyFormat.SSH_DSS.getIdentifier().getBytes());
                    dos.writeInt(dsaParams.getP().toByteArray().length);
                    dos.write(dsaParams.getP().toByteArray());
                    dos.writeInt(dsaParams.getQ().toByteArray().length);
                    dos.write(dsaParams.getQ().toByteArray());
                    dos.writeInt(dsaParams.getG().toByteArray().length);
                    dos.write(dsaParams.getG().toByteArray());
                    dos.writeInt(dsaPublicKey.getY().toByteArray().length);
                    dos.write(dsaPublicKey.getY().toByteArray());
                } else {
                    throw new IllegalArgumentException("Not a DSA public key: " + publicKey);
                }
                return Magic.getFingerprint(byteOs.toByteArray());
            } catch (IOException e) {
                LOGGER.error("[getFingerprint] failed to generate DSA fingerprint", e);
            } finally {
                try {
                    byteOs.close();
                } catch (IOException ignored) {
                }
            }

            return null;
        }
    };

    public static final FingerprintGenerator RSA = new FingerprintGenerator() {
        public String getFingerprint(PublicKey publicKey) {
            ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
            try {
                if (publicKey instanceof RSAPublicKey) {
                    RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                    DataOutputStream dos = new DataOutputStream(byteOs);
                    dos.writeInt(KeyFormat.SSH_RSA.getIdentifier().getBytes().length);
                    dos.write(KeyFormat.SSH_RSA.getIdentifier().getBytes());
                    dos.writeInt(rsaPublicKey.getPublicExponent().toByteArray().length);
                    dos.write(rsaPublicKey.getPublicExponent().toByteArray());
                    dos.writeInt(rsaPublicKey.getModulus().toByteArray().length);
                    dos.write(rsaPublicKey.getModulus().toByteArray());
                } else {
                    throw new IllegalArgumentException("Not an RSA public key: " + publicKey);
                }
                return Magic.getFingerprint(byteOs.toByteArray());
            } catch (IOException e) {
                LOGGER.error("[getFingerprint] failed to generate RSA fingerprint", e);
            } finally {
                try {
                    byteOs.close();
                } catch (IOException ignored) {
                }
            }

            return null;
        }
    };
}
