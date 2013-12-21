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
 * Enumeration of supported HTTP Signature algorithms
 */
public enum Algorithm {
    RSA_SHA1("rsa-sha1"),
    RSA_SHA256("rsa-sha256"),
    RSA_SHA512("rsa-sha512"),
    DSA_SHA1("dsa-sha1"),
    HMAC_SHA1("hmac-sha1"),
    HMAC_SHA256("hmac-sha256"),
    HMAC_SHA512("hmac-sha512"),
    SSH_RSA("ssh-rsa"),
    SSH_DSS("ssh-dss");

    private final String name;

    private Algorithm(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static Algorithm forName(String name) {
        for (Algorithm algorithm : Algorithm.values()) {
            if (algorithm.getName().equalsIgnoreCase(name)) {
                return algorithm;
            }
        }

        return null;
    }
}
