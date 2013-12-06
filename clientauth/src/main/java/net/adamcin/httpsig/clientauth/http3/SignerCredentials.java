package net.adamcin.httpsig.clientauth.http3;

import net.adamcin.httpsig.api.Signer;
import org.apache.commons.httpclient.Credentials;

public final class SignerCredentials implements Credentials {

    private Signer signer;

    public SignerCredentials(Signer signer) {
        this.signer = signer;
    }

    public Signer getSigner() {
        return signer;
    }
}
