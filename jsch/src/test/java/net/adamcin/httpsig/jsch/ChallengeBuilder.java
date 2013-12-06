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

package net.adamcin.httpsig.jsch;

import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.Challenge;

import java.util.Arrays;
import java.util.Collection;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 11/15/13
 * Time: 9:31 AM
 * To change this template use File | Settings | File Templates.
 */
public final class ChallengeBuilder {
    private final String realm;
    private final String nonce;
    private final String host;
    private final String userAgent;

    public ChallengeBuilder(String realm, String nonce, String host, String userAgent) {
        this.realm = realm;
        this.nonce = nonce;
        this.host = host;
        this.userAgent = userAgent;
    }

    public Challenge build(String fingerprint, Collection<Algorithm> algorithms) {
        return new Challenge(realm, fingerprint, nonce, host, userAgent, Arrays.asList(
                algorithms.toArray(new Algorithm[algorithms.size()])
        ));
    }
}
