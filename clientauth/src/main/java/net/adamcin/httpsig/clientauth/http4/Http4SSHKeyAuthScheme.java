package net.adamcin.httpsig.clientauth.http4;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.Signer;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.impl.auth.RFC2617Scheme;
import org.apache.http.message.BasicHeader;

public final class Http4SSHKeyAuthScheme extends RFC2617Scheme {


    public String getSchemeName() {
        return Constants.SCHEME;
    }

    public boolean isConnectionBased() {
        return false;
    }

    public boolean isComplete() {
        return true;
    }

    public Header authenticate(Credentials credentials, HttpRequest request)
            throws AuthenticationException {

        if (credentials instanceof SignerCredentials) {
            Signer signer = ((SignerCredentials) credentials).getSigner();
            System.out.println("parameters="+ this.getParameters().toString());
            System.out.println("keyId="+ this.getParameter(Constants.FINGERPRINT));
            String fingerprint = this.getParameter(Constants.FINGERPRINT);
            String nonce = this.getParameter(Constants.NONCE);
            String algorithms = this.getParameter(Constants.ALGORITHMS);

            Header hostHeader = request.getFirstHeader(Constants.HOST);
            Header userAgentHeader = request.getFirstHeader(Constants.USER_AGENT);
            String host = hostHeader != null ? hostHeader.getValue() : "";
            String userAgent = userAgentHeader != null ? userAgentHeader.getValue() : "";

            Challenge challenge = new Challenge(this.getRealm(), fingerprint, nonce, host, userAgent, Challenge.parseAlgorithms(algorithms));

            Authorization authorization = signer.sign(challenge);
            if (authorization != null) {
                return new BasicHeader(
                        Constants.AUTHORIZATION,
                        authorization.toString()
                );
            }
        }

        return null;
    }
}
