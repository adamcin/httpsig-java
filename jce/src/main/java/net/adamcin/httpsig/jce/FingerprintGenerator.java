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
