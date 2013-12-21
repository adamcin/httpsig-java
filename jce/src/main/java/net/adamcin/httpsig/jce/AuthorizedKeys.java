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

package net.adamcin.httpsig.jce;

import net.adamcin.httpsig.api.Base64;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.Verifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Factory methods for creating {@link Verifier} instances around SSH authorized_keys files
 */
public final class AuthorizedKeys {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizedKeys.class);
    private static final Pattern AUTHORIZED_KEY_PATTERN = Pattern.compile("^([^\\s]+)\\s+([^\\s]+)(\\s+([^\\s].*)|$)");
    private static final String DEFAULT_PATH = ".ssh/authorized_keys";
    private static final int GROUP_FORMAT = 1;
    private static final int GROUP_KEY = 2;
    private static final int GROUP_COMMENT = 4;
    private static final Charset ASCII = Charset.forName("US-ASCII");

    /**
     * @return a {@link Keychain} attached to the authorized_keys identities read from
     * @throws IOException if the default authorized_Keys file does not exist.
     */
    public static Keychain defaultKeychain() throws IOException {
        return newKeychain(new File(new File(System.getProperty("user.home", "/")), DEFAULT_PATH));
    }

    /**
     * Convenience method which should simplify the interaction for 99% of implementations.
     *
     * @param authorizedKeysFile File in the RFC4253 authorized_keys format that every Linux admin knows and loves,
     *                           which contains a list of public keys which are allowed for authentication
     * @return a {@link Keychain} attached to the authorized_keys identities
     */
    public static Keychain newKeychain(File authorizedKeysFile) throws IOException {
        DefaultKeychain identities = new DefaultKeychain();
        for (AuthorizedKey authorizedKey : parseAuthorizedKeys(authorizedKeysFile)) {
            identities.add(getAuthorizedKeyIdentity(authorizedKey));
        }
        return identities;
    }

    static List<AuthorizedKey> parseAuthorizedKeys(File authorizedKeys) throws IOException {
        Reader reader = null;
        try {
            reader = new InputStreamReader(new FileInputStream(authorizedKeys), ASCII);
            return parseAuthorizedKeys(reader);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // shouldn't happen
                    e.printStackTrace(System.err);
                }
            }
        }
    }

    static List<AuthorizedKey> parseAuthorizedKeys(Reader reader) throws IOException {

        List<AuthorizedKey> authorizedKeys = new ArrayList<AuthorizedKey>();
        BufferedReader bufferedReader = new BufferedReader(reader);

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            AuthorizedKey authorizedKey = parseAuthorizedKey(line);
            if (authorizedKey != null) {
                authorizedKeys.add(authorizedKey);
            }
        }

        return Collections.unmodifiableList(authorizedKeys);
    }

    static AuthorizedKey parseAuthorizedKey(String authorizedKeyString) {
        if (authorizedKeyString != null) {
            Matcher matcher = AUTHORIZED_KEY_PATTERN.matcher(authorizedKeyString);
            if (matcher.find()) {
                String format = matcher.group(GROUP_FORMAT);
                String encodedKey = matcher.group(GROUP_KEY);
                String comment = matcher.group(GROUP_COMMENT);

                return new AuthorizedKey(format, encodedKey, comment);
            }
        }
        return null;
    }

    static Key getAuthorizedKeyIdentity(AuthorizedKey authorizedKey) {
        if (authorizedKey != null) {
            byte[] keyBlob = Base64.fromBase64String(authorizedKey.getEncodedKey());
            return readPublicIdentity(keyBlob);
        }
        return null;
    }

    static final class PublicPair {
        private final KeyFormat format;
        private final KeySpec spec;

        PublicPair(KeyFormat format, KeySpec spec) {
            this.format = format;
            this.spec = spec;
        }

        public KeyFormat getFormat() {
            return format;
        }

        public KeySpec getSpec() {
            return spec;
        }
    }

    static PublicPair readPublicPair(byte[] keyBlob) {
        ByteArrayInputStream is = new ByteArrayInputStream(keyBlob);
        DataInputStream dis = new DataInputStream(is);

        String type;
        try {
            byte[] b_type = new byte[dis.readInt()];
            int r_type = dis.read(b_type);
            type = new String(b_type, ASCII);
        } catch (IOException e) {
            throw new IllegalStateException("how did an IOException get thrown from a byte array input stream?", e);
        }

        final KeyFormat keyFormat = KeyFormat.forIdentifier(type);
        KeySpec spec = null;
        try {
            switch (keyFormat) {
                case SSH_RSA:
                    byte[] b_e = new byte[dis.readInt()];
                    int r_e = dis.read(b_e);
                    BigInteger e = new BigInteger(b_e);
                    byte[] b_m = new byte[dis.readInt()];
                    int r_m = dis.read(b_m);
                    BigInteger m = new BigInteger(b_m);
                    spec = new RSAPublicKeySpec(m, e);
                    break;
                case SSH_DSS:
                    byte[] b_p = new byte[dis.readInt()];
                    int r_p = dis.read(b_p);
                    BigInteger p = new BigInteger(b_p);
                    byte[] b_q = new byte[dis.readInt()];
                    int r_q = dis.read(b_q);
                    BigInteger q = new BigInteger(b_q);
                    byte[] b_g = new byte[dis.readInt()];
                    int r_g = dis.read(b_g);
                    BigInteger g = new BigInteger(b_g);
                    byte[] b_y = new byte[dis.readInt()];
                    int r_y = dis.read(b_y);
                    BigInteger y = new BigInteger(b_y);
                    spec = new DSAPublicKeySpec(y, p, q, g);
                    break;
                case UNKOWN:
                    throw new IllegalArgumentException("unknown key format: " + type);
            }
        } catch (IOException e) {
            throw new IllegalStateException("how did an IOException get thrown from a byte array input stream?", e);
        }

        return new PublicPair(keyFormat, spec);
    }

    static Key createPublicIdentity(PublicPair pair) {
        KeyFactory keyFactory = pair.getFormat().getKeyFactory();

        assert keyFactory != null;

        try {
            PublicKey publicKey = keyFactory.generatePublic(pair.getSpec());
            return new JCEKey(pair.getFormat(), publicKey, null);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("this exception should not have been thrown.", e);
        }

        return null;
    }

    /**
     * @param keyBlob
     * @return a shiny new {@link net.adamcin.httpsig.api.Key}
     * @see <a href="http://tools.ietf.org/html/rfc4253#section-6.6">[RFC4253] Section 6.6: Public Key Algorithms</a>
     */
    static Key readPublicIdentity(byte[] keyBlob) {
        PublicPair pair = readPublicPair(keyBlob);
        return createPublicIdentity(pair);
    }

    static final class AuthorizedKey {
        private final String format;
        private final String encodedKey;
        private final String comment;

        AuthorizedKey(String format, String encodedKey, String comment) {
            this.format = format;
            this.encodedKey = encodedKey;
            this.comment = comment;
        }

        public String getFormat() {
            return format;
        }

        public String getEncodedKey() {
            return encodedKey;
        }

        public String getComment() {
            return comment;
        }

        @Override
        public String toString() {
            return String.format("%s %s %s", format, encodedKey, comment);
        }
    }
}
