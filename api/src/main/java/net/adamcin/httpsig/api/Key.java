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

package net.adamcin.httpsig.api;

import java.util.Set;

public interface Key {

    /**
     * @return the {@link Key}'s self-identification. This may end up not being unique within a keychain.
     */
    String getId();

    /**
     * @return the {@link Set} of Signature {@link Algorithm}s supported by this key.
     */
    Set<Algorithm> getAlgorithms();

    /**
     * @return true if this {@link Key} can be used for verification
     */
    boolean canVerify();

    /**
     * Verifies the {@code signatureBytes} against the {@code challengeHash} using an underlying public key
     * @param algorithm the selected Signature {@link Algorithm}
     * @param contentBytes the result of {@link SignatureContent#getContent(java.util.List, java.nio.charset.Charset)}
     * @param signatureBytes the result of {@link net.adamcin.httpsig.api.Authorization#getSignatureBytes()}
     * @return true if signature is valid
     */
    boolean verify(Algorithm algorithm, byte[] contentBytes, byte[] signatureBytes);

    /**
     * @return true if this {@link Key} can be used for signing
     */
    boolean canSign();

    /**
     * Signs the {@code challengeHash} using the specified signature {@link Algorithm}
     * @param algorithm the selected Signature {@link Algorithm}
     * @param contentBytes the result of {@link SignatureContent#getContent(java.util.List, java.nio.charset.Charset)}
     * @return byte array containing the challengeHash signature or null if a signature could not be generated.
     */
    byte[] sign(Algorithm algorithm, byte[] contentBytes);
}
