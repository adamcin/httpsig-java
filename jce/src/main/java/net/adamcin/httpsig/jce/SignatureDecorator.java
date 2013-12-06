package net.adamcin.httpsig.jce;

/**
 * Simple abstract class and key-format-specific adjustments to signatures performed by SSH clients.
 */
public abstract class SignatureDecorator {
    abstract byte[] postSign(byte[] signatureBytes);
    abstract byte[] preVerify(byte[] signatureBytes);

    public static final SignatureDecorator RSA = new SignatureDecorator() {
        @Override
        byte[] postSign(byte[] signatureBytes) {
            return signatureBytes;
        }

        @Override
        byte[] preVerify(byte[] signatureBytes) {
            final byte[] extracted = Magic.extractSignatureFromDER(signatureBytes);
            return extracted;
        }
    };

    public static final SignatureDecorator DSA = new SignatureDecorator() {
        @Override
        byte[] postSign(byte[] signatureBytes) {
            return Magic.dssPadSignature(signatureBytes);
        }

        @Override
        byte[] preVerify(byte[] signatureBytes) {
            final byte[] extracted = Magic.extractSignatureFromDER(signatureBytes);
            return Magic.dssUnpadSignature(extracted);
        }
    };
}
