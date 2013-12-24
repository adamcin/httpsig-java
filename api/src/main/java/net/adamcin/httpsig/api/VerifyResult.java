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

/**
 * Enumeration of possible results from {@link Verifier#verifyWithResult(Challenge, SignatureContent, Authorization)}
 */
public enum VerifyResult {

    /**
     * Signature is valid
     */
    SUCCESS,

    /**
     * {@link Authorization} does not declare all the headers required by the {@link Challenge}
     */
    CHALLENGE_NOT_SATISFIED,

    /**
     * Not all headers identified by the {@link Authorization} are present in the {@link SignatureContent}
     */
    INCOMPLETE_REQUEST,

    /**
     * The value of the date header falls outside of the current time of the {@link Verifier}, plus or minus the skew
     */
    EXPIRED_DATE_HEADER,

    /**
     * The {@link Verifier} cannot find a {@link Key} matching the keyId of the {@link Authorization}
     */
    KEY_NOT_FOUND,

    /**
     * The selected {@link Key} rejected the signature as invalid
     */
    FAILED_KEY_VERIFY
}
