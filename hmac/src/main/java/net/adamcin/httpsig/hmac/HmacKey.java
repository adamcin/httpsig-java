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

package net.adamcin.httpsig.hmac;

import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class HmacKey implements Key {

    private final String keyId;
    private final String secret;

    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final Logger LOGGER = LoggerFactory.getLogger(HmacKey.class);

    /**
     * Instantiates a new HMAC key with an identifier and a secret used to sign
     * @param keyId The keys identifier
     * @param secret The secret used to sign
     */
    public HmacKey(String keyId, String secret) {
        if (keyId == null) {
            throw new NullPointerException("keyId must not be null");
        }
        if (secret == null) {
            throw new NullPointerException("secret must not be null");
        }
        this.keyId = keyId;
        this.secret = secret;
    }

    /**
     * @return the {@link net.adamcin.httpsig.api.Key}'s self-identification. This may end up not being unique within a keychain.
     */
    public String getId() {
        return keyId;
    }

    /**
     * @return the {@link java.util.Set} of Signature {@link net.adamcin.httpsig.api.Algorithm}s supported by this key.
     */
    public Set<Algorithm> getAlgorithms() {
        Set<Algorithm> algorithms = new HashSet<Algorithm>();

        algorithms.add(Algorithm.HMAC_SHA512);
        algorithms.add(Algorithm.HMAC_SHA256);

        return algorithms;
    }

    /**
     * HMAC Keys can always be used to verify
     * @return always true
     */
    public boolean canVerify() {
        return true;
    }

    /**
     * Verifies the {@code signatureBytes} against the {@code challengeHash} using an underlying public key
     * @param algorithm the selected Signature {@link net.adamcin.httpsig.api.Algorithm}
     * @param contentBytes the result of {@link net.adamcin.httpsig.api.RequestContent#getContent(java.util.List, java.nio.charset.Charset)}
     * @param signatureBytes the result of {@link net.adamcin.httpsig.api.Authorization#getSignatureBytes()}
     * @return true if signature is valid
     */
    public boolean verify(Algorithm algorithm, byte[] contentBytes, byte[] signatureBytes) {
        if(getAlgorithms().contains(algorithm)){
            byte[] generatedSig = sign(algorithm, contentBytes);
            return Arrays.equals(generatedSig, signatureBytes);
        }

        return false;
    }

    /**
     * Maps http-signatures spec algorithm names to Java
     * @param algorithm http-signature spec algorithm name
     * @return Java algorithm name
     */
    private String mapAlgorithm(Algorithm algorithm) {
        if("hmac-sha512".equalsIgnoreCase(algorithm.getName())){
            return "HmacSHA512";
        }else if("hmac-sha256".equalsIgnoreCase(algorithm.getName())){
            return "HmacSHA256";
        }else{
            throw new IllegalArgumentException(String.format("Unsupported algorithm: %s", algorithm.getName()));
        }
    }

    /**
     * HMAC Keys can always be used to sign
     * @return always true
     */
    public boolean canSign() {
        return true;
    }

    /**
     * Signs the {@code challengeHash} using the specified signature {@link net.adamcin.httpsig.api.Algorithm}
     * @param algorithm the selected Signature {@link net.adamcin.httpsig.api.Algorithm}
     * @param contentBytes the result of {@link net.adamcin.httpsig.api.RequestContent#getContent(java.util.List, java.nio.charset.Charset)}
     * @return byte array containing the challengeHash signature or null if a signature could not be generated.
     */
    public byte[] sign(Algorithm algorithm, byte[] contentBytes) {
        try{

            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), mapAlgorithm(algorithm));
            Mac mac = Mac.getInstance(mapAlgorithm(algorithm));
            mac.init(secretKeySpec);
            return mac.doFinal(contentBytes);

        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("[sign] failed to sign content.", e);
        } catch (InvalidKeyException e) {
            LOGGER.error("[sign] failed to sign content.", e);
        }

        return EMPTY_BYTES;
    }
}