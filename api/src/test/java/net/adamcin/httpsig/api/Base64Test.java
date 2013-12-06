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

import org.junit.Test;

import static org.junit.Assert.*;
import static org.apache.commons.codec.binary.Base64.encodeBase64;
import static org.apache.commons.codec.binary.Base64.decodeBase64;


public class Base64Test {

    @Test
    public void testTo() {

        byte[] foobarBytes = "foobar".getBytes();
        assertEquals(
                "foobar should be encoded the same way as in commons-codec",
                new String(encodeBase64(foobarBytes, false), Constants.CHARSET),
                Base64.toBase64String(foobarBytes)
        );
    }

    @Test
    public void testFrom() {
        byte[] foobarBytes = "foobar".getBytes();
        String encoded = new String(encodeBase64(foobarBytes, false), Constants.CHARSET);

        assertEquals("foobar (encoded) should be decoded the same way as in commons-codec",
                     new String(decodeBase64(encoded.getBytes(Constants.CHARSET))),
                     new String(Base64.fromBase64String(encoded)));
    }
}
