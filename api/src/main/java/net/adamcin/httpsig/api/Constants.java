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

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Constant values used by the Signature Specification
 */
public final class Constants {

    /**
     * Identifier for the Signature Authentication scheme
     */
    public static final String SCHEME = "Signature";

    /**
     * Http response header representing a server authentication challenge
     * @see <a href="http://www.ietf.org/rfc/rfc2617.txt">RFC 2617: HTTP Authentication: Basic and Digest Access Authentication</a>
     */
    public static final String CHALLENGE = "WWW-Authenticate";

    /**
     * Challenge header "realm" parameter
     */
    public static final String REALM = "realm";

    /**
     * Parameter name for challenge-selected SSH Public Key Fingerprint
     */
    public static final String KEY_ID = "keyId";

    public static final String HEADER_REQUEST_LINE = "request-line";

    public static final String HEADER_DATE = "date";

    public static final List<String> DEFAULT_HEADERS = Arrays.asList(HEADER_DATE);

    /**
     * Http request header representing client credentials
     * @see <a href="http://www.ietf.org/rfc/rfc2617.txt">RFC 2617: HTTP Authentication: Basic and Digest Access Authentication</a>
     */
    public static final String AUTHORIZATION = "Authorization";

    /**
     * Parameter name for the "headers" authorization parameter
     */
    public static final String HEADERS = "headers";

    /**
     * Parameter name for the "signature" authorization parameter
     */
    public static final String SIGNATURE = "signature";

    /**
     * Challenge header "algorithms" parameter
     */
    public static final String ALGORITHMS = "algorithms";

    /**
     * Challenge header "algorithm" parameter
     */
    public static final String ALGORITHM = "algorithm";

    /**
     * Default encoding for header values.
     */
    public static final Charset CHARSET = Charset.forName("ISO-8859-1");

    /**
     *
     */
    public static final Pattern RFC2617_PARAM = Pattern.compile("(^|\\s)(\\w+)=\"([^\"]*)\"");

    public static final List<String> parseTokens(String tokens) {
        if (tokens == null || tokens.trim().isEmpty()) {
            return Collections.emptyList();
        } else {
            List<String> tokenList = new ArrayList<String>();
            String[] _tokens = tokens.trim().split("\\s+");
            for (String _token : _tokens) {
                tokenList.add(_token);
            }
            return Collections.unmodifiableList(tokenList);
        }
    }

    public static final String constructTokensString(List<String> tokens) {
        StringBuilder sb = new StringBuilder();
        if (tokens != null) {
            for (String token : tokens) {
                sb.append(token).append(" ");
            }
        }
        return sb.toString();
    }

    public static final Map<String, String> parseRFC2617(String header) {
        Map<String, String> params = new HashMap<String, String>();
        final Matcher matcher = RFC2617_PARAM.matcher(header);
        while (matcher.find()) {
            params.put(matcher.group(2), matcher.group(3));
        }
        return Collections.unmodifiableMap(params);
    }

    public static final String constructRFC2617(Map<String, String> params) {
        StringBuilder sb = new StringBuilder(SCHEME);
        if (params != null && !params.isEmpty()) {
            for (Map.Entry<String, String> param : params.entrySet()) {
                sb.append(" ").append(param.getKey()).append("=\"").append(param.getValue()).append("\"").append(",");
            }
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    public static final KeyIdentifier DEFAULT_KEY_IDENTIFIER = new KeyIdentifier() {
        public String getId(Key key) { return key.getId(); }
    };

    public static final Collection<Algorithm> ALL_SUPPORTED_ALGORITHMS = Arrays.asList(Algorithm.values());

    public static final Challenge PREEMPTIVE_CHALLENGE = new Challenge("<preemptive>", DEFAULT_HEADERS, ALL_SUPPORTED_ALGORITHMS);

    private Constants() {
    }

}
