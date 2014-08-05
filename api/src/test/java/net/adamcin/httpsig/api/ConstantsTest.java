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

import java.util.*;

import static org.junit.Assert.assertEquals;

public class ConstantsTest {

    /**
     * Added for defect-2; Provided test case {@code headers="date content-type"}
     */
    @Test
    public void testConstructTokensString() {

        assertEquals("headers should be empty if provided with a null list", "",
                Constants.constructTokensString(null));

        assertEquals("headers should be empty if provided with an empty list", "",
                Constants.constructTokensString(Collections.<String>emptyList()));

        assertEquals("should be a single token with no leading or trailing whitespace", "date",
                Constants.constructTokensString(Arrays.asList("date")));

        assertEquals("headers should be separated by one space with no trailing spaces", "date content-type",
                Constants.constructTokensString(Arrays.asList("date", "content-type")));
    }

    /**
     * Added for defect-2; should support new and old formats
     * Provided test case {@code headers="date content-type"} which should remain equivalent to
     * {@code headers="date content-type "}
     */
    @Test
    public void testParseTokens() {
        List<String> tokens = Arrays.asList("date", "content-type");
        List<String> parsedExpected = Constants.parseTokens("date content-type");
        assertEquals("expected format should parse correctly", tokens, parsedExpected);

        List<String> parsedLegacy = Constants.parseTokens("date content-type ");
        assertEquals("legacy format should parse correctly", tokens, parsedLegacy);
    }

    /**
     * Added for defect-2; Provided test case:
     * {@code Signature keyId="unit", algorithm="hmac-sha1", headers="Content-Type Date", signature="8sY4dne3lta76PDMM+AUVaKkV7o="}
     * which should be
     * {@code Signature keyId="unit",algorithm="hmac-sha1",headers="Content-Type Date",signature="yIy5ujWnGZ0pKVR7vY6Qv08WfLE="}
     */
    @Test
    public void testConstructRFC2617() {
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put("keyId", "unit");
        params.put("algorithm", "hmac-sha1");
        params.put("headers", "Content-Type Date");
        params.put("signature", "yIy5ujWnGZ0pKVR7vY6Qv08WfLE=");

        String formatted = Constants.constructRFC2617(params);

        assertEquals("RFC 2617 string should be properly formatted",
                "Signature keyId=\"unit\",algorithm=\"hmac-sha1\",headers=\"Content-Type Date\",signature=\"yIy5ujWnGZ0pKVR7vY6Qv08WfLE=\"",
                formatted);
    }

    /**
     * Added for defect-2; maintain support for both new and old formats.
     * {@code Signature keyId="unit", algorithm="hmac-sha1", headers="Content-Type Date", signature="8sY4dne3lta76PDMM+AUVaKkV7o="}
     * {@code Signature keyId="unit",algorithm="hmac-sha1",headers="Content-Type Date",signature="yIy5ujWnGZ0pKVR7vY6Qv08WfLE="}
     */
    @Test
    public void testParseRFC2617() {
        final String expectedFormat = "Signature keyId=\"unit\",algorithm=\"hmac-sha1\",headers=\"Content-Type Date\",signature=\"yIy5ujWnGZ0pKVR7vY6Qv08WfLE=\"";
        final String legacyFormat = "Signature keyId=\"unit\", algorithm=\"hmac-sha1\", headers=\"Content-Type Date\", signature=\"yIy5ujWnGZ0pKVR7vY6Qv08WfLE=\"";

        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put("keyId", "unit");
        params.put("algorithm", "hmac-sha1");
        params.put("headers", "Content-Type Date");
        params.put("signature", "yIy5ujWnGZ0pKVR7vY6Qv08WfLE=");

        Map<String, String> parsedExpected = Constants.parseRFC2617(expectedFormat);
        for (Map.Entry<String, String> entry : params.entrySet()) {
            assertEquals("parsed param values should be the same", entry.getValue(), parsedExpected.get(entry.getKey()));
        }

        Map<String, String> parsedLegacy = Constants.parseRFC2617(legacyFormat);
        for (Map.Entry<String, String> entry : params.entrySet()) {
            assertEquals("parsed param values should be the same", entry.getValue(), parsedLegacy.get(entry.getKey()));
        }
    }
}
