package net.adamcin.httpsig.jce;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of peculiar SSH byte array algorithms
 */
public final class Magic {

    private static final char[] fingerPrintChars = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * Computes the MD5 fingerprint of the public key blob
     *
     * @param keyBlob base64-decoded byte array containing the public key spec
     * @return
     * @see <a href="http://tools.ietf.org/html/rfc4716#section-4">[RFC4716] Section 4: Public Key Fingerprints</a>
     */
    public static String getFingerprint(byte[] keyBlob) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
            byte[] foo = digest.digest(keyBlob);

            StringBuilder sb = new StringBuilder();
            int bar;
            for (int i = 0; i < foo.length; i++) {
                bar = foo[i] & 0xff;
                sb.append(fingerPrintChars[(bar >>> 4) & 0xf]);
                sb.append(fingerPrintChars[(bar) & 0xf]);
                if (i + 1 < foo.length) {
                    sb.append(":");
                }
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // should not happen in a standard JVM
        }

        return null;
    }

    public static byte[] extractSignatureFromDER(byte[] signatureBytes) {
        if (signatureBytes[0] == 0 && signatureBytes[1] == 0 && signatureBytes[2] == 0) {
            int i = 0;
            int j; // length decoder
            j =     ((signatureBytes[i++] << 24) & 0xff000000) |
                    ((signatureBytes[i++] << 16) & 0x00ff0000) |
                    ((signatureBytes[i++] <<  8) & 0x0000ff00) |
                    ((signatureBytes[i++]      ) & 0x000000ff);
            i += j; // i == index after first field length + value
            j =     ((signatureBytes[i++] << 24) & 0xff000000) |
                    ((signatureBytes[i++] << 16) & 0x00ff0000) |
                    ((signatureBytes[i++] <<  8) & 0x0000ff00) |
                    ((signatureBytes[i++]      ) & 0x000000ff);
            byte[] tmp = new byte[j]; // i == index of second field value, j == length of second field value
            System.arraycopy(signatureBytes, i, tmp, 0, j); //
            signatureBytes = tmp;
        }
        return signatureBytes;
    }

    /**
     * Pad {@code r} and {@code s} to 160-bit (20 byte) integers
     * @param signatureBytes
     * @return
     */
    public static byte[] dssPadSignature(byte[] signatureBytes) {
        // sig is in ASN.1
        // SEQUENCE::={ r INTEGER, s INTEGER }
        int len = 0;
        int index = 3;
        len = signatureBytes[index++] & 0xff;
        byte[] r = new byte[len];
        System.arraycopy(signatureBytes, index, r, 0, r.length);
        index = index + len + 1;
        len = signatureBytes[index++] & 0xff;
        byte[] s = new byte[len];
        System.arraycopy(signatureBytes, index, s, 0, s.length);

        byte[] result = new byte[40];

        // result must be 40 bytes, but length of r and s may not be 20 bytes

        System.arraycopy(r,
                         (r.length > 20) ? 1 : 0,
                         result,
                         (r.length > 20) ? 0 : 20 - r.length,
                         (r.length > 20) ? 20 : r.length);
        System.arraycopy(s,
                         (s.length > 20) ? 1 : 0,
                         result,
                         (s.length > 20) ? 20 : 40 - s.length,
                         (s.length > 20) ? 20 : s.length);

        return result;

    }

    /**
     * Remove padding from 160-bit integers, {@code r} and {@code s}
     * @param signatureBytes
     * @return
     */
    public static byte[] dssUnpadSignature(byte[] signatureBytes) {
        // ASN.1
        int frst = ((signatureBytes[0] & 0x80) != 0 ? 1 : 0);
        int scnd = ((signatureBytes[20] & 0x80) != 0 ? 1 : 0);

        int length = signatureBytes.length + 6 + frst + scnd;
        byte[] result = new byte[length];
        result[0] = (byte) 0x30;
        result[1] = (byte) 0x2c;
        result[1] += frst;
        result[1] += scnd;
        result[2] = (byte) 0x02;
        result[3] = (byte) 0x14;
        result[3] += frst;
        System.arraycopy(signatureBytes, 0, result, 4 + frst, 20);
        result[4 + result[3]] = (byte) 0x02;
        result[5 + result[3]] = (byte) 0x14;
        result[5 + result[3]] += scnd;
        System.arraycopy(signatureBytes, 20, result, 6 + result[3] + scnd, 20);
        return result;
    }
}
