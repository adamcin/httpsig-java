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

package net.adamcin.httpsig.sshjce;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * The "ssh-rsa" key format has the following specific encoding:
 *
 *    string    "ssh-rsa"
 *    mpint     e
 *    mpint     n
 *
 * Here the 'e' and 'n' parameters form the signature key blob.
 *
 * Signing and verifying using this key format is performed according to the RSASSA-PKCS1-v1_5 scheme in [RFC3447]
 * using the SHA-1 hash.
 *
 * The resulting signature is encoded as follows:
 *
 *    string    "ssh-rsa"
 *    string    rsa_signature_blob
 *
 * The value for 'rsa_signature_blob' is encoded as a string containing {@code s} (which is an integer, without lengths
 * or padding, unsigned, and in network byte order).
 */
public final class SSHRSASignature extends Signature {

    private final Signature wrapped;

    public SSHRSASignature() throws NoSuchAlgorithmException {
        super("ssh-rsa");
        this.wrapped = Signature.getInstance("SHA1withRSA");
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.wrapped.initVerify(publicKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.wrapped.initSign(privateKey);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        this.wrapped.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.wrapped.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        return this.wrapped.sign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        final byte[] extracted = Magic.extractSignatureFromDER(sigBytes);
        return this.wrapped.verify(extracted);
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        this.wrapped.setParameter(param, value);
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return this.wrapped.getParameter(param);
    }
}
