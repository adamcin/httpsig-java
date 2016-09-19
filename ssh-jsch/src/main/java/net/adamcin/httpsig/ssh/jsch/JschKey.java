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

package net.adamcin.httpsig.ssh.jsch;

import com.jcraft.jsch.Buffer;
import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Signature;
import com.jcraft.jsch.jce.SignatureDSA;
import com.jcraft.jsch.jce.SignatureRSA;
import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.ssh.jce.FingerprintableKey;
import net.adamcin.httpsig.ssh.jce.Magic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

/**
 *
 */
public class JschKey implements FingerprintableKey {
    private static final Logger LOGGER = LoggerFactory.getLogger(JschKey.class);

    private final String fingerprint;
    private final Algorithm algorithm;
    private final Identity identity;

    public JschKey(Identity identity) {
        this.fingerprint = Magic.getFingerprint(identity.getPublicKeyBlob());
        this.identity = identity;
        this.algorithm = Algorithm.forName(identity.getAlgName());
    }

    public String getId() {
        return this.fingerprint;
    }

    public String getFingerprint() {
        return this.fingerprint;
    }

    public Set<Algorithm> getAlgorithms() {
        return Collections.unmodifiableSet(this.algorithm == null ? new HashSet<Algorithm>() : new HashSet<Algorithm>(Arrays.asList(this.algorithm)));
    }

    /**
     * {@inheritDoc}
     * @param algorithm the selected Signature {@link Algorithm}
     * @param challengeHash the result of {@link net.adamcin.httpsig.api.RequestContent#getContent(java.util.List, java.nio.charset.Charset)}
     * @param signatureBytes the result of {@link net.adamcin.httpsig.api.Authorization#getSignatureBytes()}
     * @return true if verified
     */
    public boolean verify(Algorithm algorithm, byte[] challengeHash, byte[] signatureBytes) {
        if (algorithm == this.algorithm) {
            try {
                Signature signature = getSignature(challengeHash);
                return signature.verify(signatureBytes);
            } catch (Exception e) {
                LOGGER.error("[verify] signature verification failed.", e);
            }
        }

        return false;
    }

    public boolean canVerify() {
        try {
            return this.getSignature("test".getBytes()) != null;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean canSign() {
        try {
            return identity.getSignature("test".getBytes()) != null;
        } catch (Exception e) {
            return false;
        }
    }

    private Signature getSignature(byte[] challengeHash) throws Exception {
        if (Algorithm.SSH_RSA == this.algorithm) {
            SignatureRSA signature = new SignatureRSA();

            Buffer buf = new Buffer(this.identity.getPublicKeyBlob());

            signature.init();
            buf.getString(); // read the format string first
            byte[] e = buf.getString();
            byte[] n = buf.getString();
            signature.setPubKey(e, n);
            signature.update(challengeHash);
            return signature;
        } else if (Algorithm.SSH_DSS == this.algorithm) {
            SignatureDSA signature = new SignatureDSA();

            Buffer buf = new Buffer(this.identity.getPublicKeyBlob());

            signature.init();
            buf.getString(); // read the format string first
            byte[] p = buf.getString();
            byte[] q = buf.getString();
            byte[] g = buf.getString();
            byte[] pub_array = buf.getString();
            signature.setPubKey(pub_array, p, q, g);
            signature.update(challengeHash);
            return signature;
        } else {
            throw new Exception("Unsupported public key algorithm: " + identity.getAlgName());
        }
    }

    /**
     * {@inheritDoc}
     * @param algorithm the selected Signature {@link Algorithm}
     * @param challengeHash the result of {@link net.adamcin.httpsig.api.RequestContent#getContent(java.util.List, java.nio.charset.Charset)}
     * @return the generated signature
     */
    public byte[] sign(Algorithm algorithm, byte[] challengeHash) {
        return identity.getSignature(challengeHash);
    }

    public static Keychain getIdentities(JSch jSch) {
        ArrayList<JschKey> identities = new ArrayList<JschKey>();
        Vector _identities = jSch.getIdentityRepository().getIdentities();
        if (_identities != null) {
            for (Object obj : _identities) {
                identities.add(new JschKey((Identity) obj));
            }
        }

        return new DefaultKeychain(Collections.unmodifiableList(identities));
    }
}
